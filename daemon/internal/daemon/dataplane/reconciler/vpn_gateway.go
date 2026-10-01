package reconciler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"

	juneau "github.com/1outres/juneau/controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func vpnIdentity(uid types.UID) [16]uint8 {
	sum := sha256.Sum256([]byte(uid))
	var id [16]uint8
	copy(id[:], sum[:16])
	return id
}

func vpnGatewayPodName(vpn *juneau.VPN) string {
	hash := sha256.Sum256([]byte(vpn.UID))
	prefix := vpn.Name
	if len(prefix) > 32 {
		prefix = prefix[:32]
	}
	return "vpn-" + prefix + "-" + hex.EncodeToString(hash[:8])
}

func resolveVPNGateway(ctx context.Context, cl client.Client, vpn *juneau.VPN) (*juneau.Subnet, *corev1.Pod, *juneau.NetworkInterface, *juneau.NetworkEndpoint, error) {
	if vpn.UID == "" || vpn.DeletionTimestamp != nil || vpn.Status.ObservedGeneration != vpn.Generation || !meta.IsStatusConditionTrue(vpn.Status.Conditions, "Ready") {
		return nil, nil, nil, nil, fmt.Errorf("VPN %s/%s is not Ready", vpn.Namespace, vpn.Name)
	}
	ready := meta.FindStatusCondition(vpn.Status.Conditions, "Ready")
	if ready == nil || ready.ObservedGeneration != vpn.Generation {
		return nil, nil, nil, nil, fmt.Errorf("VPN %s/%s has stale status", vpn.Namespace, vpn.Name)
	}
	var subnet juneau.Subnet
	if err := cl.Get(ctx, client.ObjectKey{Name: vpn.Spec.Subnet}, &subnet); err != nil {
		return nil, nil, nil, nil, err
	}
	if subnet.Spec.Vpc != vpn.Spec.Vpc || subnet.DeletionTimestamp != nil || subnet.Status.VNI == 0 || subnet.Status.GatewayMAC == "" || !meta.IsStatusConditionTrue(subnet.Status.Conditions, juneau.SubnetStatusReady) || (subnet.Generation != 0 && meta.FindStatusCondition(subnet.Status.Conditions, juneau.SubnetStatusReady).ObservedGeneration != subnet.Generation) {
		return nil, nil, nil, nil, fmt.Errorf("VPN gateway Subnet is not Ready")
	}
	var pods corev1.PodList
	if err := cl.List(ctx, &pods, client.InNamespace(vpn.Namespace)); err != nil {
		return nil, nil, nil, nil, err
	}
	var pod *corev1.Pod
	for i := range pods.Items {
		p := &pods.Items[i]
		for _, ref := range p.OwnerReferences {
			if p.Name == vpnGatewayPodName(vpn) && ref.Kind == "VPN" && ref.UID == vpn.UID && ref.Name == vpn.Name {
				if pod != nil {
					return nil, nil, nil, nil, fmt.Errorf("multiple VPN gateway Pods")
				}
				pod = p
			}
		}
	}
	if pod == nil || pod.UID == "" || pod.Spec.NodeName == "" || pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning {
		return nil, nil, nil, nil, fmt.Errorf("VPN gateway Pod is not Running")
	}
	podReady := false
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
			podReady = true
		}
	}
	if !podReady {
		return nil, nil, nil, nil, fmt.Errorf("VPN gateway Pod is not Ready")
	}
	var interfaces juneau.NetworkInterfaceList
	if err := cl.List(ctx, &interfaces, client.InNamespace(vpn.Namespace)); err != nil {
		return nil, nil, nil, nil, err
	}
	var nic *juneau.NetworkInterface
	for i := range interfaces.Items {
		n := &interfaces.Items[i]
		if n.Name == pod.Name+".eth0" {
			if nic != nil {
				return nil, nil, nil, nil, fmt.Errorf("multiple VPN gateway NICs")
			}
			nic = n
		}
	}
	if nic == nil || nic.DeletionTimestamp != nil || nic.Spec.PodRef.Name != pod.Name || nic.Spec.PodRef.Interface != "eth0" || nic.Spec.PodRef.UID != string(pod.UID) || nic.Spec.NodeName != pod.Spec.NodeName || nic.Spec.Subnet != subnet.Name || nic.Status.Phase != juneau.NetworkInterfacePhaseReady || nic.Status.ObservedGeneration != nic.Generation {
		return nil, nil, nil, nil, fmt.Errorf("VPN gateway eth0 is not Ready")
	}
	addr, _, err := net.ParseCIDR(nic.Status.Address)
	if err != nil || addr.To4() == nil {
		return nil, nil, nil, nil, fmt.Errorf("VPN gateway eth0 has no IPv4 address")
	}
	var endpoints juneau.NetworkEndpointList
	if err := cl.List(ctx, &endpoints, client.InNamespace(vpn.Namespace)); err != nil {
		return nil, nil, nil, nil, err
	}
	var endpoint *juneau.NetworkEndpoint
	for i := range endpoints.Items {
		e := &endpoints.Items[i]
		if e.Name != pod.Name+".eth0" {
			continue
		}
		if endpoint != nil {
			return nil, nil, nil, nil, fmt.Errorf("multiple VPN gateway endpoints")
		}
		endpoint = e
	}
	if endpoint == nil || endpoint.Spec.PodRef == nil || endpoint.Spec.PodRef.Name != pod.Name || endpoint.Spec.PodRef.Interface != "eth0" || endpoint.DeletionTimestamp != nil || endpoint.Spec.Kind != juneau.EndpointKindPod || endpoint.Spec.PodRef.UID != string(pod.UID) || endpoint.Spec.Subnet != subnet.Name || endpoint.Spec.Address != nic.Status.Address || endpoint.Spec.NodeName != pod.Spec.NodeName {
		return nil, nil, nil, nil, fmt.Errorf("VPN gateway endpoint does not match eth0")
	}
	if _, err := net.ParseMAC(endpoint.Spec.MACAddress); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("VPN gateway endpoint MAC: %w", err)
	}
	return &subnet, pod, nic, endpoint, nil
}
