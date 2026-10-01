package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"time"

	juneau "github.com/1outres/juneau/controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	vpnFinalizer     = "vpn.juneau.loutres.me/gateway"
	vpnOwnerUIDLabel = "juneau.loutres.me/vpn-uid"
	vpnOwnerKeyLabel = "juneau.loutres.me/vpn-key"
	vpnSecretVersion = "juneau.loutres.me/psk-version"
	vpnRetry         = 5 * time.Second
)

var errVPNClaimConflict = errors.New("VPN tunnel claim conflict")

type VPNReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
	TunnelPool   string
	GatewayImage string
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=vpns,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=vpns/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=vpns/finalizers,verbs=update
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=vpcs;subnets;externalnetworks;routetables;allocationpools;networkinterfaces;vpcpeerings;transitgateways;transitgatewayroutetables;transitgatewayattachments;vpcendpoints,verbs=get;list;watch
// +kubebuilder:rbac:groups=discovery.k8s.io,resources=endpointslices,verbs=get;list;watch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationclaims;elasticips,verbs=get;list;watch;create;delete
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch;create;delete
// +kubebuilder:rbac:groups=core,resources=secrets;services,verbs=get;list;watch

func (r *VPNReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var vpn juneau.VPN
	if err := r.Get(ctx, req.NamespacedName, &vpn); err != nil {
		if apierrors.IsNotFound(err) {
			return r.cleanupOrphans(ctx, req, nil)
		}
		return ctrl.Result{}, err
	}
	if !vpn.DeletionTimestamp.IsZero() {
		return r.teardown(ctx, &vpn)
	}
	if !controllerutil.ContainsFinalizer(&vpn, vpnFinalizer) {
		controllerutil.AddFinalizer(&vpn, vpnFinalizer)
		if err := r.Update(ctx, &vpn); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}
	if _, err := r.cleanupOrphans(ctx, req, &vpn); err != nil {
		return ctrl.Result{}, err
	}
	if r.TunnelPool == "" || r.GatewayImage == "" {
		return r.waitStopped(ctx, &vpn, "ConfigurationMissing", "VPN tunnel pool and gateway image must be configured")
	}
	var pool juneau.AllocationPool
	if err := r.Get(ctx, client.ObjectKey{Name: r.TunnelPool}, &pool); err != nil {
		return r.dependencyErrorStopped(ctx, &vpn, "TunnelPoolMissing", err)
	}
	if err := validateVPNTunnelPool(&pool); err != nil {
		return r.waitStopped(ctx, &vpn, "InvalidTunnelPool", err.Error())
	}
	var vpc juneau.Vpc
	if err := r.Get(ctx, client.ObjectKey{Name: vpn.Spec.Vpc}, &vpc); err != nil {
		return r.dependencyErrorStopped(ctx, &vpn, "VpcMissing", err)
	}
	var subnet juneau.Subnet
	if err := r.Get(ctx, client.ObjectKey{Name: vpn.Spec.Subnet}, &subnet); err != nil {
		return r.dependencyErrorStopped(ctx, &vpn, "SubnetMissing", err)
	}
	if subnet.Spec.Vpc != vpc.Name || !subnet.DeletionTimestamp.IsZero() {
		return r.waitStopped(ctx, &vpn, "SubnetNotReady", "Subnet must be active in the VPN Vpc")
	}
	if !conditionReady(subnet.Status.Conditions, juneau.SubnetStatusReady, subnet.Generation) {
		if subnet.Status.ObservedGeneration < subnet.Generation && conditionReady(subnet.Status.Conditions, juneau.SubnetStatusReady, 0) && r.gatewayPodPlacementValid(ctx, &vpn, &subnet) {
			return r.wait(ctx, &vpn, "SubnetNotReady", "waiting for gateway Subnet to reconcile")
		}
		if vpcPendingOnGatewayVPN(ctx, r.Client, &vpc, &subnet) && r.gatewayPodPlacementValid(ctx, &vpn, &subnet) {
			return r.wait(ctx, &vpn, "SubnetNotReady", "waiting for gateway Subnet to reconcile")
		}
		return r.waitStopped(ctx, &vpn, "SubnetNotReady", "Subnet must be Ready in the VPN Vpc")
	}
	var external juneau.ExternalNetwork
	if err := r.Get(ctx, client.ObjectKey{Name: vpn.Spec.ExternalNetwork}, &external); err != nil {
		return r.dependencyErrorStopped(ctx, &vpn, "ExternalNetworkMissing", err)
	}
	if !external.DeletionTimestamp.IsZero() {
		return r.waitStopped(ctx, &vpn, "ExternalNetworkDeleting", "ExternalNetwork is being deleted")
	}
	var secret corev1.Secret
	if err := r.Get(ctx, client.ObjectKey{Namespace: vpn.Namespace, Name: vpn.Spec.PSKSecretRef.Name}, &secret); err != nil {
		if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		return r.waitStopped(ctx, &vpn, "SecretMissing", "PSK Secret is missing")
	}
	if len(secret.Data[vpn.Spec.PSKSecretRef.Key]) == 0 {
		return r.waitStopped(ctx, &vpn, "SecretInvalid", "PSK Secret key is empty")
	}
	remoteRoutes, advertisedRoutes, err := r.gatewayRoutes(ctx, &vpn, &vpc, &subnet)
	if err != nil {
		return r.waitStopped(ctx, &vpn, "RoutesNotReady", err.Error())
	}
	local, err := r.ensureClaim(ctx, &vpn, "local")
	if errors.Is(err, errVPNClaimConflict) {
		return r.waitStopped(ctx, &vpn, "OwnershipConflict", err.Error())
	}
	if err != nil {
		return ctrl.Result{}, err
	}
	remote, err := r.ensureClaim(ctx, &vpn, "remote")
	if errors.Is(err, errVPNClaimConflict) {
		return r.waitStopped(ctx, &vpn, "OwnershipConflict", err.Error())
	}
	if err != nil {
		return ctrl.Result{}, err
	}
	if !claimReady(local) || !claimReady(remote) {
		return r.waitStopped(ctx, &vpn, "Allocating", "waiting for tunnel IP allocation")
	}
	if local.Status.Value.IP == remote.Status.Value.IP {
		return r.waitStopped(ctx, &vpn, "InvalidAllocation", "tunnel addresses must be different")
	}
	if vpn.Status.LocalTunnelIP != local.Status.Value.IP || vpn.Status.RemoteTunnelIP != remote.Status.Value.IP {
		if err := r.setStatus(ctx, &vpn, metav1.ConditionFalse, "Allocating", "tunnel addresses allocated", "", local.Status.Value.IP, remote.Status.Value.IP); err != nil {
			return ctrl.Result{}, err
		}
	}
	var eip juneau.ElasticIP
	eipKey := client.ObjectKey{Namespace: vpn.Namespace, Name: vpnEIPName(&vpn)}
	if err := r.Get(ctx, eipKey, &eip); apierrors.IsNotFound(err) {
		eip = juneau.ElasticIP{ObjectMeta: metav1.ObjectMeta{Namespace: vpn.Namespace, Name: eipKey.Name}, Spec: juneau.ElasticIPSpec{ExternalNetwork: vpn.Spec.ExternalNetwork, RequestedIP: vpn.Spec.RequestedPublicIP}}
		if err := controllerutil.SetControllerReference(&vpn, &eip, r.Scheme); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.Create(ctx, &eip); err != nil {
			return ctrl.Result{}, err
		}
		return r.waitStopped(ctx, &vpn, "Allocating", "waiting for public IP allocation")
	} else if err != nil {
		return ctrl.Result{}, err
	}
	if !ownedByVPN(&eip, &vpn) || eip.Spec.ExternalNetwork != vpn.Spec.ExternalNetwork || eip.Spec.RequestedIP != vpn.Spec.RequestedPublicIP {
		return r.waitStopped(ctx, &vpn, "OwnershipConflict", "ElasticIP name is used by another resource")
	}
	if eip.DeletionTimestamp != nil || eip.Status.Address == "" || eip.Status.Phase == juneau.ElasticIPPhaseError || !conditionReady(eip.Status.Conditions, "Allocated", eip.Generation) {
		return r.waitStopped(ctx, &vpn, "Allocating", "waiting for public IP allocation")
	}
	desired, err := vpnGatewayPod(&vpn, &secret, r.GatewayImage, local.Status.Value.IP, remote.Status.Value.IP, eip.Name, eip.Status.Address, remoteRoutes, advertisedRoutes)
	if err != nil {
		return ctrl.Result{}, err
	}
	var pod corev1.Pod
	podKey := client.ObjectKeyFromObject(desired)
	if err := r.Get(ctx, podKey, &pod); apierrors.IsNotFound(err) {
		if err := controllerutil.SetControllerReference(&vpn, desired, r.Scheme); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.Create(ctx, desired); err != nil {
			return ctrl.Result{}, err
		}
		return r.wait(ctx, &vpn, "Starting", "waiting for gateway Pod")
	} else if err != nil {
		return ctrl.Result{}, err
	}
	if !ownedByVPN(&pod, &vpn) {
		return r.wait(ctx, &vpn, "OwnershipConflict", "gateway Pod name is used by another resource")
	}
	bootstrapPeer, err := r.peeringAdvertisementAdded(ctx, &vpn, &pod, advertisedRoutes)
	if err != nil {
		return ctrl.Result{}, err
	}
	if pending, err := r.gatewayTablePendingOnVPN(ctx, &vpn, &vpc, &subnet); err != nil {
		return ctrl.Result{}, err
	} else if pending {
		if !bootstrapPeer {
			preserveGatewayRoutes(desired, &pod)
		}
	} else if pending, err := r.transitTablePendingOnVPN(ctx, &vpn, &vpc, &subnet); err != nil {
		return ctrl.Result{}, err
	} else if pending {
		if !bootstrapPeer {
			preserveGatewayRoutes(desired, &pod)
		}
	} else if pending, err := r.peeringTablePendingOnVPN(ctx, &vpn); err != nil {
		return ctrl.Result{}, err
	} else if pending {
		if !bootstrapPeer {
			preserveGatewayRoutes(desired, &pod)
		}
	}
	if !vpnPodMatches(&pod, desired) || pod.Status.Phase == corev1.PodFailed || pod.Status.Phase == corev1.PodSucceeded {
		if pod.DeletionTimestamp == nil {
			if err := r.Delete(ctx, &pod); err != nil {
				return ctrl.Result{}, err
			}
		}
		return r.wait(ctx, &vpn, "Replacing", "waiting for gateway Pod replacement")
	}
	if pod.DeletionTimestamp != nil || pod.UID == "" || pod.Status.Phase != corev1.PodRunning {
		return r.wait(ctx, &vpn, "Starting", "gateway Pod is not Running")
	}
	for _, name := range []string{"eth0", "ext0"} {
		var nic juneau.NetworkInterface
		if err := r.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: networkInterfaceNameForPod(pod.Name, name)}, &nic); err != nil {
			return r.dependencyError(ctx, &vpn, "InterfaceMissing", err)
		}
		if nic.Spec.PodRef.UID != string(pod.UID) || nic.Spec.PodRef.Interface != name || nic.Status.Phase != juneau.NetworkInterfacePhaseReady || nic.Status.ObservedGeneration != nic.Generation {
			return r.wait(ctx, &vpn, "InterfaceNotReady", "gateway interface is not Ready")
		}
		if name == "eth0" && nic.Spec.Subnet != vpn.Spec.Subnet || name == "ext0" && (nic.Spec.ElasticIP != eip.Name || nic.Status.Address != eip.Status.Address+"/32") {
			return r.wait(ctx, &vpn, "InterfaceNotReady", "gateway interface does not match VPN placement")
		}
	}
	if eip.Status.Phase != juneau.ElasticIPPhaseAttached || eip.Status.Attachment == nil || eip.Status.Attachment.Kind != juneau.ElasticIPStatusAttachmentKindNetworkInterface || eip.Status.Attachment.Name != networkInterfaceNameForPod(pod.Name, "ext0") {
		return r.wait(ctx, &vpn, "PublicIPNotAttached", "public IP is not attached to the gateway")
	}
	if !podReady(&pod) {
		if err := r.setStatus(ctx, &vpn, metav1.ConditionFalse, "Connecting", "waiting for IKEv2 child SA and BGP session", eip.Status.Address, local.Status.Value.IP, remote.Status.Value.IP); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: vpnRetry}, nil
	}
	return ctrl.Result{}, r.setStatus(ctx, &vpn, metav1.ConditionTrue, "GatewayReady", "gateway passed its health check", eip.Status.Address, local.Status.Value.IP, remote.Status.Value.IP)
}

func (r *VPNReconciler) gatewayPodPlacementValid(ctx context.Context, vpn *juneau.VPN, subnet *juneau.Subnet) bool {
	if subnet.Status.VNI == 0 {
		return false
	}
	if subnet.Spec.NetworkACL != "" {
		var acl juneau.NetworkACL
		if err := r.Get(ctx, client.ObjectKey{Name: subnet.Spec.NetworkACL}, &acl); err != nil || acl.DeletionTimestamp != nil || acl.Spec.Vpc != vpn.Spec.Vpc || acl.Status.ACLID == 0 {
			return false
		}
	}
	var pod corev1.Pod
	if err := r.Get(ctx, client.ObjectKey{Namespace: vpn.Namespace, Name: vpnPodName(vpn)}, &pod); err != nil || !ownedByVPN(&pod, vpn) || pod.DeletionTimestamp != nil || pod.UID == "" || pod.Status.Phase != corev1.PodRunning {
		return false
	}
	var attachments []juneau.PodNetworkAttachment
	if err := json.Unmarshal([]byte(pod.Annotations[juneau.PodAnnotationNetworks]), &attachments); err != nil || len(attachments) != 2 || attachments[0].Interface != "eth0" || attachments[0].Subnet != subnet.Name || attachments[1].Interface != "ext0" || attachments[1].ElasticIP != vpnEIPName(vpn) {
		return false
	}
	for _, name := range []string{"eth0", "ext0"} {
		var nic juneau.NetworkInterface
		err := r.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: networkInterfaceNameForPod(pod.Name, name)}, &nic)
		if apierrors.IsNotFound(err) {
			// The Pod controller may still be creating NICs while this VPN route is pending.
			continue
		}
		if err != nil || nic.DeletionTimestamp != nil || nic.Spec.PodRef.UID != string(pod.UID) || nic.Spec.PodRef.Name != pod.Name || nic.Spec.PodRef.Interface != name {
			return false
		}
		if name == "eth0" && nic.Spec.Subnet != subnet.Name || name == "ext0" && nic.Spec.ElasticIP != vpnEIPName(vpn) {
			return false
		}
	}
	return true
}

func validateVPNTunnelPool(pool *juneau.AllocationPool) error {
	if pool.DeletionTimestamp != nil || pool.Spec.Type != juneau.AllocationTypeIP || pool.Spec.IP == nil {
		return fmt.Errorf("VPN tunnel pool must be an active IP AllocationPool")
	}
	if len(pool.Spec.IP.CIDRs) == 0 && len(pool.Spec.IP.Ranges) == 0 {
		return fmt.Errorf("VPN tunnel pool has no addresses")
	}
	for _, raw := range pool.Spec.IP.CIDRs {
		p, err := netip.ParsePrefix(raw)
		if err != nil || !p.Addr().Is4() {
			return fmt.Errorf("VPN tunnel pool must contain only IPv4 CIDRs")
		}
	}
	for _, rng := range pool.Spec.IP.Ranges {
		a, e := netip.ParseAddr(rng.Start)
		b, f := netip.ParseAddr(rng.End)
		if e != nil || f != nil || !a.Is4() || !b.Is4() || b.Less(a) {
			return fmt.Errorf("VPN tunnel pool must contain only valid IPv4 ranges")
		}
	}
	return nil
}

func vpnOwnerKey(namespace, name string) string {
	hash := sha256.Sum256([]byte(namespace + "/" + name))
	return hex.EncodeToString(hash[:16])
}
func vpnClaim(vpn *juneau.VPN, pool, side string) *juneau.AllocationClaim {
	hash := sha256.Sum256([]byte(string(vpn.UID)))
	name := "vpn-" + hex.EncodeToString(hash[:12]) + "-" + side
	return &juneau.AllocationClaim{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{vpnOwnerUIDLabel: string(vpn.UID), vpnOwnerKeyLabel: vpnOwnerKey(vpn.Namespace, vpn.Name)}}, Spec: juneau.AllocationClaimSpec{PoolRefs: []juneau.AllocationPoolReference{{Name: pool}}, ResourceRef: juneau.AllocationResourceReference{APIVersion: juneau.GroupVersion.String(), Kind: "VPN", Namespace: vpn.Namespace, Name: vpn.Name}, Attribute: "status." + side + "TunnelIP"}}
}
func vpnClaimMatches(claim *juneau.AllocationClaim, vpn *juneau.VPN, side string) bool {
	if len(claim.Spec.PoolRefs) != 1 || claim.Spec.PoolRefs[0].Name == "" {
		return false
	}
	want := vpnClaim(vpn, claim.Spec.PoolRefs[0].Name, side)
	return claim.Name == want.Name && claim.Labels[vpnOwnerUIDLabel] == string(vpn.UID) && claim.Labels[vpnOwnerKeyLabel] == want.Labels[vpnOwnerKeyLabel] && reflect.DeepEqual(claim.Spec, want.Spec)
}
func claimReady(claim *juneau.AllocationClaim) bool {
	ip, err := netip.ParseAddr(claim.Status.Value.IP)
	return err == nil && ip.Is4() && claim.Status.Phase == juneau.AllocationClaimPhaseAllocated && conditionReady(claim.Status.Conditions, juneau.AllocationClaimStatusReady, claim.Generation)
}
func (r *VPNReconciler) ensureClaim(ctx context.Context, vpn *juneau.VPN, side string) (*juneau.AllocationClaim, error) {
	desired := vpnClaim(vpn, r.TunnelPool, side)
	var claim juneau.AllocationClaim
	err := r.Get(ctx, client.ObjectKey{Name: desired.Name}, &claim)
	if apierrors.IsNotFound(err) {
		if err := r.Create(ctx, desired); err != nil {
			return nil, err
		}
		return desired, nil
	}
	if err != nil {
		return nil, err
	}
	if !vpnClaimMatches(&claim, vpn, side) || !reflect.DeepEqual(claim.Spec, desired.Spec) || claim.DeletionTimestamp != nil {
		return nil, fmt.Errorf("%w: AllocationClaim %s has conflicting ownership or configuration", errVPNClaimConflict, claim.Name)
	}
	return &claim, nil
}
func (r *VPNReconciler) gatewayTablePendingOnVPN(ctx context.Context, vpn *juneau.VPN, vpc *juneau.Vpc, subnet *juneau.Subnet) (bool, error) {
	name := subnet.Spec.RouteTable
	if name == "" {
		name = vpc.Status.MainRouteTable
	}
	var table juneau.RouteTable
	if err := r.Get(ctx, client.ObjectKey{Name: name}, &table); err != nil {
		return false, err
	}
	return !conditionReady(table.Status.Conditions, juneau.RouteTableStatusReady, table.Generation) && vpnTableReady(&table, vpn), nil
}

func (r *VPNReconciler) transitTablePendingOnVPN(ctx context.Context, vpn *juneau.VPN, vpc *juneau.Vpc, subnet *juneau.Subnet) (bool, error) {
	name := subnet.Spec.RouteTable
	if name == "" {
		name = vpc.Status.MainRouteTable
	}
	var table juneau.RouteTable
	if err := r.Get(ctx, client.ObjectKey{Name: name}, &table); err != nil {
		return false, err
	}
	for _, route := range table.Status.Routes {
		if route.Via.Type != juneau.ViaTransitGateway || route.TransitGatewayRouteTable == "" {
			continue
		}
		var transit juneau.TransitGatewayRouteTable
		if err := r.Get(ctx, client.ObjectKey{Name: route.TransitGatewayRouteTable}, &transit); err != nil {
			return false, err
		}
		ready := meta.FindStatusCondition(transit.Status.Conditions, juneau.TransitGatewayRouteTableStatusReady)
		if ready == nil || ready.Status != metav1.ConditionFalse || ready.ObservedGeneration != transit.Generation || ready.Reason != transitGatewayRouteTableReasonVPNRoutePending || transit.Status.PendingVPN != vpn.Namespace+"/"+vpn.Name {
			continue
		}
		var attachments juneau.TransitGatewayAttachmentList
		if err := r.List(ctx, &attachments); err != nil {
			return false, err
		}
		for _, candidate := range transit.Spec.Routes {
			for i := range attachments.Items {
				a := &attachments.Items[i]
				if candidate.Attachment != a.Name || a.Spec.Vpc != vpc.Name || a.Spec.TransitGateway != transit.Spec.TransitGateway || a.DeletionTimestamp != nil || !conditionReady(a.Status.Conditions, juneau.TransitGatewayAttachmentStatusReady, a.Generation) {
					continue
				}
				prefix, err := netip.ParsePrefix(candidate.Dst)
				if err == nil {
					own := vpnRouteForAddress(table.Spec.Routes, prefix.Addr())
					if own != nil && sameVPNRoute(own, vpn) {
						return true, nil
					}
				}
			}
		}
	}
	return false, nil
}

func (r *VPNReconciler) peeringTablePendingOnVPN(ctx context.Context, vpn *juneau.VPN) (bool, error) {
	var tables juneau.RouteTableList
	if err := r.List(ctx, &tables); err != nil {
		return false, err
	}
	prefixes := make(map[string]bool)
	for i := range tables.Items {
		table := &tables.Items[i]
		if table.Spec.Vpc != vpn.Spec.Vpc || table.DeletionTimestamp != nil {
			continue
		}
		for _, route := range table.Spec.Routes {
			if sameVPNRoute(&route, vpn) {
				prefixes[route.Dst] = true
			}
		}
	}
	if len(prefixes) == 0 {
		return false, nil
	}
	var peerings juneau.VpcPeeringList
	if err := r.List(ctx, &peerings); err != nil {
		return false, err
	}
	key := vpn.Namespace + "/" + vpn.Name
	for i := range tables.Items {
		table := &tables.Items[i]
		ready := meta.FindStatusCondition(table.Status.Conditions, juneau.RouteTableStatusReady)
		if table.Spec.Vpc == vpn.Spec.Vpc || table.DeletionTimestamp != nil || ready == nil || ready.Status != metav1.ConditionFalse || ready.ObservedGeneration != table.Generation || ready.Reason != routeTableReasonVPNEndpointPending || !routeTableVPNPending(&table.Status, key) {
			continue
		}
		for _, route := range table.Spec.Routes {
			if route.Via.Type != juneau.ViaVpcPeering || !prefixes[route.Dst] {
				continue
			}
			for j := range peerings.Items {
				peering := &peerings.Items[j]
				if peering.Name == route.Via.VpcPeering && peering.DeletionTimestamp == nil {
					if peer, ok := peering.Spec.PeerOf(table.Spec.Vpc); ok && peer == vpn.Spec.Vpc {
						return true, nil
					}
				}
			}
		}
	}
	return false, nil
}

func (r *VPNReconciler) peeringAdvertisementAdded(ctx context.Context, vpn *juneau.VPN, pod *corev1.Pod, advertised []string) (bool, error) {
	if len(pod.Spec.Containers) != 1 {
		return false, nil
	}
	var current []string
	found := false
	for _, env := range pod.Spec.Containers[0].Env {
		if env.Name == "VPN_ADVERTISED_ROUTES" && env.ValueFrom == nil {
			if err := json.Unmarshal([]byte(env.Value), &current); err != nil {
				return false, nil
			}
			found = true
		}
	}
	if !found {
		return false, nil
	}
	var subnets juneau.SubnetList
	if err := r.List(ctx, &subnets); err != nil {
		return false, err
	}
	for i := range subnets.Items {
		subnet := &subnets.Items[i]
		if subnet.Spec.Vpc == vpn.Spec.Vpc || !slices.Contains(advertised, subnet.Spec.CIDR) || slices.Contains(current, subnet.Spec.CIDR) {
			continue
		}
		pending, err := r.peeringSubnetPendingOnVPN(ctx, vpn, subnet)
		if err != nil {
			return false, err
		}
		if pending {
			return true, nil
		}
	}
	return false, nil
}

func preserveGatewayRoutes(desired, actual *corev1.Pod) {
	if len(actual.Spec.Containers) != 1 {
		return
	}
	for i := range desired.Spec.Containers[0].Env {
		want := &desired.Spec.Containers[0].Env[i]
		if want.Name != "VPN_REMOTE_ROUTES" && want.Name != "VPN_ADVERTISED_ROUTES" {
			continue
		}
		for _, current := range actual.Spec.Containers[0].Env {
			if current.Name == want.Name && current.ValueFrom == nil {
				want.Value = current.Value
			}
		}
	}
}

func vpnPodName(vpn *juneau.VPN) string {
	hash := sha256.Sum256([]byte(string(vpn.UID)))
	prefix := vpn.Name
	if len(prefix) > 32 {
		prefix = prefix[:32]
	}
	return "vpn-" + prefix + "-" + hex.EncodeToString(hash[:8])
}
func vpnEIPName(vpn *juneau.VPN) string { return vpnPodName(vpn) }
func vpnPodMatches(actual, desired *corev1.Pod) bool {
	if actual.Annotations[juneau.PodAnnotationNetworks] != desired.Annotations[juneau.PodAnnotationNetworks] || actual.Annotations[vpnSecretVersion] != desired.Annotations[vpnSecretVersion] || actual.Spec.HostNetwork || len(actual.Spec.Containers) != 1 || len(actual.Spec.Volumes) == 0 {
		return false
	}
	a, d := actual.Spec.Containers[0], desired.Spec.Containers[0]
	if a.Name != d.Name || a.Image != d.Image || !reflect.DeepEqual(a.Command, d.Command) || !reflect.DeepEqual(a.Args, d.Args) || !reflect.DeepEqual(a.Env, d.Env) || !reflect.DeepEqual(a.Ports, d.Ports) || a.SecurityContext == nil || a.SecurityContext.Privileged == nil || !*a.SecurityContext.Privileged || a.ReadinessProbe == nil || a.ReadinessProbe.Exec == nil || !reflect.DeepEqual(a.ReadinessProbe.Exec.Command, d.ReadinessProbe.Exec.Command) || a.ReadinessProbe.PeriodSeconds != d.ReadinessProbe.PeriodSeconds {
		return false
	}
	for _, want := range d.VolumeMounts {
		found := false
		for _, v := range a.VolumeMounts {
			if v.Name == want.Name && v.MountPath == want.MountPath && v.ReadOnly {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	for _, v := range actual.Spec.Volumes {
		if v.Name == "psk" && v.Secret != nil && v.Secret.SecretName == desired.Spec.Volumes[0].Secret.SecretName && reflect.DeepEqual(v.Secret.Items, desired.Spec.Volumes[0].Secret.Items) {
			return true
		}
	}
	return false
}
func ownedByVPN(obj client.Object, vpn *juneau.VPN) bool {
	for _, ref := range obj.GetOwnerReferences() {
		if ref.UID == vpn.UID && ref.Kind == "VPN" && ref.APIVersion == juneau.GroupVersion.String() && ref.Name == vpn.Name && ref.Controller != nil && *ref.Controller {
			return true
		}
	}
	return false
}
func podReady(pod *corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}
func conditionReady(conditions []metav1.Condition, kind string, generation int64) bool {
	c := meta.FindStatusCondition(conditions, kind)
	return c != nil && c.Status == metav1.ConditionTrue && (generation == 0 || c.ObservedGeneration == generation)
}
func vpnGatewayPod(vpn *juneau.VPN, secret *corev1.Secret, image, local, remote, eip, publicIP string, remoteRoutes, advertisedRoutes []string) (*corev1.Pod, error) {
	nets, err := json.Marshal([]juneau.PodNetworkAttachment{{Interface: "eth0", Subnet: vpn.Spec.Subnet}, {Interface: "ext0", ElasticIP: eip}})
	if err != nil {
		return nil, err
	}
	remoteJSON, err := json.Marshal(remoteRoutes)
	if err != nil {
		return nil, err
	}
	advertisedJSON, err := json.Marshal(advertisedRoutes)
	if err != nil {
		return nil, err
	}
	privileged := true
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: vpnPodName(vpn), Namespace: vpn.Namespace, Annotations: map[string]string{juneau.PodAnnotationNetworks: string(nets), vpnSecretVersion: secret.ResourceVersion}}, Spec: corev1.PodSpec{RestartPolicy: corev1.RestartPolicyAlways, Containers: []corev1.Container{{Name: "gateway", Image: image, ImagePullPolicy: corev1.PullIfNotPresent, SecurityContext: &corev1.SecurityContext{Privileged: &privileged}, Ports: []corev1.ContainerPort{{Name: "ike", ContainerPort: 500, Protocol: corev1.ProtocolUDP}, {Name: "nat-t", ContainerPort: 4500, Protocol: corev1.ProtocolUDP}}, Env: []corev1.EnvVar{{Name: "LOCAL_TUNNEL_IP", Value: local}, {Name: "REMOTE_TUNNEL_IP", Value: remote}, {Name: "LOCAL_ASN", Value: fmt.Sprint(vpn.Spec.LocalASN)}, {Name: "REMOTE_ASN", Value: fmt.Sprint(vpn.Spec.RemoteASN)}, {Name: "PEER_IKE_ID", Value: vpn.Spec.PeerIKEID}, {Name: "PUBLIC_IP", Value: publicIP}, {Name: "VPN_REMOTE_ROUTES", Value: string(remoteJSON)}, {Name: "VPN_ADVERTISED_ROUTES", Value: string(advertisedJSON)}, {Name: "VPN_PSK_FILE", Value: "/etc/juneau/vpn/psk"}}, VolumeMounts: []corev1.VolumeMount{{Name: "psk", MountPath: "/etc/juneau/vpn", ReadOnly: true}}, ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: []string{"vpn-gateway", "health"}}}, PeriodSeconds: 5}}}, Volumes: []corev1.Volume{{Name: "psk", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: secret.Name, Items: []corev1.KeyToPath{{Key: vpn.Spec.PSKSecretRef.Key, Path: "psk"}}}}}}}}, nil
}
func (r *VPNReconciler) allocatedAddresses(ctx context.Context, vpn *juneau.VPN) (public, local, remote string, err error) {
	addresses := []*string{&local, &remote}
	for i, side := range []string{"local", "remote"} {
		var claim juneau.AllocationClaim
		if getErr := r.Get(ctx, client.ObjectKey{Name: vpnClaim(vpn, "", side).Name}, &claim); getErr != nil {
			if apierrors.IsNotFound(getErr) {
				continue
			}
			return "", "", "", getErr
		}
		if vpnClaimMatches(&claim, vpn, side) && claim.DeletionTimestamp == nil && claimReady(&claim) {
			*addresses[i] = claim.Status.Value.IP
		}
	}
	if local != "" && local == remote {
		local, remote = "", ""
	}
	var eip juneau.ElasticIP
	if getErr := r.Get(ctx, client.ObjectKey{Namespace: vpn.Namespace, Name: vpnEIPName(vpn)}, &eip); getErr != nil {
		if apierrors.IsNotFound(getErr) {
			return "", local, remote, nil
		}
		return "", "", "", getErr
	}
	ip, parseErr := netip.ParseAddr(eip.Status.Address)
	if ownedByVPN(&eip, vpn) && eip.Spec.ExternalNetwork == vpn.Spec.ExternalNetwork && eip.Spec.RequestedIP == vpn.Spec.RequestedPublicIP && eip.DeletionTimestamp == nil && (eip.Status.Phase == juneau.ElasticIPPhaseAvailable || eip.Status.Phase == juneau.ElasticIPPhaseAttached) && conditionReady(eip.Status.Conditions, "Allocated", eip.Generation) && parseErr == nil && ip.Is4() {
		public = eip.Status.Address
	}
	return public, local, remote, nil
}

func (r *VPNReconciler) waitStopped(ctx context.Context, vpn *juneau.VPN, reason, message string) (ctrl.Result, error) {
	if err := r.stopGateway(ctx, vpn); err != nil {
		return ctrl.Result{}, err
	}
	return r.wait(ctx, vpn, reason, message)
}

func (r *VPNReconciler) wait(ctx context.Context, vpn *juneau.VPN, reason, message string) (ctrl.Result, error) {
	public, local, remote, err := r.allocatedAddresses(ctx, vpn)
	if err != nil {
		return ctrl.Result{}, err
	}
	if err := r.setStatus(ctx, vpn, metav1.ConditionFalse, reason, message, public, local, remote); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: vpnRetry}, nil
}
func (r *VPNReconciler) dependencyError(ctx context.Context, vpn *juneau.VPN, reason string, err error) (ctrl.Result, error) {
	if apierrors.IsNotFound(err) {
		return r.wait(ctx, vpn, reason, err.Error())
	}
	return ctrl.Result{}, err
}

func (r *VPNReconciler) dependencyErrorStopped(ctx context.Context, vpn *juneau.VPN, reason string, err error) (ctrl.Result, error) {
	if apierrors.IsNotFound(err) {
		return r.waitStopped(ctx, vpn, reason, err.Error())
	}
	return ctrl.Result{}, err
}
func (r *VPNReconciler) setStatus(ctx context.Context, vpn *juneau.VPN, ready metav1.ConditionStatus, reason, message, public, local, remote string) error {
	updated := *vpn.Status.DeepCopy()
	updated.ObservedGeneration = vpn.Generation
	updated.PublicIP = public
	updated.LocalTunnelIP = local
	updated.RemoteTunnelIP = remote
	meta.SetStatusCondition(&updated.Conditions, metav1.Condition{Type: "Ready", Status: ready, Reason: reason, Message: message, ObservedGeneration: vpn.Generation})
	if reflect.DeepEqual(vpn.Status, updated) {
		return nil
	}
	vpn.Status = updated
	return r.Status().Update(ctx, vpn)
}
func (r *VPNReconciler) cleanupOrphans(ctx context.Context, req ctrl.Request, current *juneau.VPN) (ctrl.Result, error) {
	var claims juneau.AllocationClaimList
	if err := r.List(ctx, &claims, client.MatchingLabels{vpnOwnerKeyLabel: vpnOwnerKey(req.Namespace, req.Name)}); err != nil {
		return ctrl.Result{}, err
	}
	pending := false
	for i := range claims.Items {
		claim := &claims.Items[i]
		if claim.Spec.ResourceRef.Kind != "VPN" || claim.Spec.ResourceRef.Namespace != req.Namespace || claim.Spec.ResourceRef.Name != req.Name {
			continue
		}
		uid := claim.Labels[vpnOwnerUIDLabel]
		if uid == "" || current != nil && uid == string(current.UID) {
			continue
		}
		side := ""
		switch claim.Spec.Attribute {
		case "status.localTunnelIP":
			side = "local"
		case "status.remoteTunnelIP":
			side = "remote"
		default:
			continue
		}
		old := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: req.Name, Namespace: req.Namespace, UID: types.UID(uid)}}
		if !vpnClaimMatches(claim, old, side) {
			continue
		}
		for _, obj := range []client.Object{&corev1.Pod{}, &juneau.ElasticIP{}} {
			err := r.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: vpnPodName(old)}, obj)
			if err == nil {
				pending = true
				break
			}
			if !apierrors.IsNotFound(err) {
				return ctrl.Result{}, err
			}
		}
		if pending {
			continue
		}
		if claim.DeletionTimestamp == nil {
			if err := r.Delete(ctx, claim); err != nil && !apierrors.IsNotFound(err) {
				return ctrl.Result{}, err
			}
		}
		pending = true
	}
	if pending {
		return ctrl.Result{RequeueAfter: vpnRetry}, nil
	}
	return ctrl.Result{}, nil
}
func (r *VPNReconciler) stopGateway(ctx context.Context, vpn *juneau.VPN) error {
	var pod corev1.Pod
	err := r.Get(ctx, client.ObjectKey{Namespace: vpn.Namespace, Name: vpnPodName(vpn)}, &pod)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !ownedByVPN(&pod, vpn) {
		return fmt.Errorf("gateway Pod %s is not owned by VPN", pod.Name)
	}
	if pod.DeletionTimestamp == nil {
		return r.Delete(ctx, &pod)
	}
	return nil
}
func (r *VPNReconciler) teardown(ctx context.Context, vpn *juneau.VPN) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(vpn, vpnFinalizer) {
		return ctrl.Result{}, nil
	}
	var tables juneau.RouteTableList
	if err := r.List(ctx, &tables); err != nil {
		return ctrl.Result{}, err
	}
	for _, table := range tables.Items {
		for _, route := range table.Spec.Routes {
			if route.Via.Type == juneau.ViaVPN && route.Via.VPN != nil && route.Via.VPN.Namespace == vpn.Namespace && route.Via.VPN.Name == vpn.Name {
				return r.wait(ctx, vpn, "RouteInUse", fmt.Sprintf("RouteTable %s still references this VPN", table.Name))
			}
		}
	}
	for _, obj := range []client.Object{&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: vpnPodName(vpn), Namespace: vpn.Namespace}}, &juneau.ElasticIP{ObjectMeta: metav1.ObjectMeta{Name: vpnEIPName(vpn), Namespace: vpn.Namespace}}} {
		if err := r.Get(ctx, client.ObjectKeyFromObject(obj), obj); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return ctrl.Result{}, err
		}
		if !ownedByVPN(obj, vpn) {
			return r.wait(ctx, vpn, "OwnershipConflict", fmt.Sprintf("%s is not owned by VPN", obj.GetName()))
		}
		if obj.GetDeletionTimestamp() == nil {
			if err := r.Delete(ctx, obj); err != nil {
				return ctrl.Result{}, err
			}
		}
		return r.wait(ctx, vpn, "Deleting", "waiting for gateway and public IP deletion")
	}
	for _, side := range []string{"local", "remote"} {
		var claim juneau.AllocationClaim
		if err := r.Get(ctx, client.ObjectKey{Name: vpnClaim(vpn, "", side).Name}, &claim); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return ctrl.Result{}, err
		}
		if !vpnClaimMatches(&claim, vpn, side) {
			return r.wait(ctx, vpn, "OwnershipConflict", "tunnel claim is not owned by VPN")
		}
		if claim.DeletionTimestamp == nil {
			if err := r.Delete(ctx, &claim); err != nil {
				return ctrl.Result{}, err
			}
		}
		return r.wait(ctx, vpn, "Deleting", "waiting for tunnel address release")
	}
	controllerutil.RemoveFinalizer(vpn, vpnFinalizer)
	return ctrl.Result{}, r.Update(ctx, vpn)
}
func (r *VPNReconciler) SetupWithManager(mgr ctrl.Manager) error {
	mapOwned := func(_ context.Context, obj client.Object) []reconcile.Request {
		for _, ref := range obj.GetOwnerReferences() {
			if ref.Kind == "VPN" && ref.APIVersion == juneau.GroupVersion.String() {
				return []reconcile.Request{{NamespacedName: client.ObjectKey{Namespace: obj.GetNamespace(), Name: ref.Name}}}
			}
		}
		return nil
	}
	mapClaim := func(_ context.Context, obj client.Object) []reconcile.Request {
		c, ok := obj.(*juneau.AllocationClaim)
		if !ok || c.Spec.ResourceRef.Kind != "VPN" {
			return nil
		}
		return []reconcile.Request{{NamespacedName: client.ObjectKey{Namespace: c.Spec.ResourceRef.Namespace, Name: c.Spec.ResourceRef.Name}}}
	}
	mapSecret := func(ctx context.Context, obj client.Object) []reconcile.Request {
		var list juneau.VPNList
		if err := r.List(ctx, &list, client.InNamespace(obj.GetNamespace())); err != nil {
			return nil
		}
		var out []reconcile.Request
		for _, v := range list.Items {
			if v.Spec.PSKSecretRef.Name == obj.GetName() {
				out = append(out, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&v)})
			}
		}
		return out
	}
	mapDependencies := func(ctx context.Context, obj client.Object) []reconcile.Request {
		var list juneau.VPNList
		if err := r.List(ctx, &list); err != nil {
			return nil
		}
		var out []reconcile.Request
		for _, v := range list.Items {
			relevant := v.Spec.Vpc == obj.GetName() || v.Spec.Subnet == obj.GetName() || v.Spec.ExternalNetwork == obj.GetName() || r.TunnelPool == obj.GetName()
			switch resource := obj.(type) {
			case *juneau.Subnet:
				relevant = true
			case *juneau.RouteTable:
				relevant = relevant || v.Spec.Vpc == resource.Spec.Vpc
			case *juneau.VpcPeering, *juneau.TransitGatewayRouteTable, *juneau.TransitGatewayAttachment, *juneau.VpcEndpoint, *juneau.NetworkInterface, *discoveryv1.EndpointSlice, *corev1.Service:
				relevant = true
			}
			if relevant {
				out = append(out, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&v)})
			}
		}
		return out
	}
	mapNIC := func(ctx context.Context, obj client.Object) []reconcile.Request {
		ni, ok := obj.(*juneau.NetworkInterface)
		if !ok {
			return nil
		}
		var pod corev1.Pod
		if err := r.Get(ctx, client.ObjectKey{Namespace: ni.Namespace, Name: ni.Spec.PodRef.Name}, &pod); err == nil && string(pod.UID) == ni.Spec.PodRef.UID {
			return append(mapOwned(ctx, &pod), mapDependencies(ctx, obj)...)
		}
		return mapDependencies(ctx, obj)
	}
	return ctrl.NewControllerManagedBy(mgr).For(&juneau.VPN{}).Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(mapOwned)).Watches(&juneau.ElasticIP{}, handler.EnqueueRequestsFromMapFunc(mapOwned)).Watches(&juneau.AllocationClaim{}, handler.EnqueueRequestsFromMapFunc(mapClaim)).Watches(&juneau.NetworkInterface{}, handler.EnqueueRequestsFromMapFunc(mapNIC)).Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(mapSecret)).Watches(&juneau.Vpc{}, handler.EnqueueRequestsFromMapFunc(mapDependencies)).Watches(&juneau.Subnet{}, handler.EnqueueRequestsFromMapFunc(mapDependencies)).Watches(&juneau.ExternalNetwork{}, handler.EnqueueRequestsFromMapFunc(mapDependencies)).Watches(&juneau.AllocationPool{}, handler.EnqueueRequestsFromMapFunc(mapDependencies)).Watches(&juneau.RouteTable{}, handler.EnqueueRequestsFromMapFunc(mapDependencies)).Watches(&juneau.VpcPeering{}, handler.EnqueueRequestsFromMapFunc(mapDependencies)).Watches(&juneau.TransitGatewayRouteTable{}, handler.EnqueueRequestsFromMapFunc(mapDependencies)).Watches(&juneau.TransitGatewayAttachment{}, handler.EnqueueRequestsFromMapFunc(mapDependencies)).Watches(&juneau.VpcEndpoint{}, handler.EnqueueRequestsFromMapFunc(mapDependencies)).Watches(&discoveryv1.EndpointSlice{}, handler.EnqueueRequestsFromMapFunc(mapDependencies)).Watches(&corev1.Service{}, handler.EnqueueRequestsFromMapFunc(mapDependencies)).Named("vpn").Complete(r)
}
