package reconciler

import (
	"context"
	"net"

	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/policy"
)

// SGMembership keeps sg_membership_map in sync with NetworkInterface
// objects cluster-wide. The map is keyed by (vpc_id, ipv4) so the data
// plane can answer both "what SGs does this Pod belong to" (egress
// evaluator's self lookup) and "what SGs does that peer belong to"
// (ingress / from-SG resolution) using the same table.
//
// Inputs:
//   - NetworkInterface (every event re-keys by NWIF namespace/name)
//   - Subnet, Vpc fan-outs so a delayed VpcID / status.address change
//     re-evaluates affected NWIFs.
type SGMembership struct {
	client client.Client
	store  *policy.MembershipStore
}

func NewSGMembership(cl client.Client, store *policy.MembershipStore) *SGMembership {
	return &SGMembership{client: cl, store: store}
}

func (r *SGMembership) Name() string { return "sg-membership" }

func (r *SGMembership) Reconcile(ctx context.Context, key string) error {
	namespace, name, err := toolscache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}

	var iface juneauv1alpha1.NetworkInterface
	err = r.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &iface)
	if apierrors.IsNotFound(err) {
		return r.store.Delete(key)
	}
	if err != nil {
		return err
	}

	// Resolve the address. status.address may carry a CIDR (e.g.
	// "10.16.0.5/24") or a bare IP. Use ParseIP first, falling back to
	// ParseCIDR for the CIDR form.
	if iface.Status.Address == "" {
		return r.store.Delete(key)
	}
	ip := net.ParseIP(iface.Status.Address)
	if ip == nil {
		ipNet, _, err := net.ParseCIDR(iface.Status.Address)
		if err != nil {
			return r.store.Delete(key)
		}
		ip = ipNet
	}
	ipBE, ok := policy.IPv4ToBE(ip)
	if !ok {
		return r.store.Delete(key)
	}

	// Resolve VPC. We go through Subnet → Vpc → Status.VpcID, mirroring
	// what the existing reconcilers do.
	if iface.Spec.Subnet == "" {
		return r.store.Delete(key)
	}
	var subnet juneauv1alpha1.Subnet
	if err := r.client.Get(ctx, client.ObjectKey{Name: iface.Spec.Subnet}, &subnet); err != nil {
		if apierrors.IsNotFound(err) {
			return r.store.Delete(key)
		}
		return err
	}
	var vpc juneauv1alpha1.Vpc
	if err := r.client.Get(ctx, client.ObjectKey{Name: subnet.Spec.Vpc}, &vpc); err != nil {
		if apierrors.IsNotFound(err) {
			return r.store.Delete(key)
		}
		return err
	}
	if vpc.Status.VpcID == 0 {
		// VpcID not yet allocated; bail and let a later event re-fire.
		return r.store.Delete(key)
	}

	gids := make([]uint32, 0, len(iface.Status.EffectiveSecurityGroups))
	for _, sg := range iface.Status.EffectiveSecurityGroups {
		if sg.GroupID == 0 {
			continue
		}
		gids = append(gids, sg.GroupID)
	}
	if len(gids) == 0 {
		return r.store.Delete(key)
	}

	zap.S().Infow("sg-membership: applying",
		"key", key,
		"vpc_id", vpc.Status.VpcID,
		"address", iface.Status.Address,
		"groupIDs", gids)
	return r.store.Apply(key, policy.MembershipKey{
		VpcID: vpc.Status.VpcID,
		IPv4:  ipBE,
	}, policy.MembershipValue{GroupIDs: gids})
}

// FanOutVpcToInterfaces re-enqueues every NetworkInterface whose Subnet
// belongs to the given Vpc. Used so a late VpcID allocation propagates.
func (r *SGMembership) FanOutVpcToInterfaces(obj any) []string {
	vpc, ok := obj.(*juneauv1alpha1.Vpc)
	if !ok {
		return nil
	}
	var ifaces juneauv1alpha1.NetworkInterfaceList
	if err := r.client.List(context.Background(), &ifaces); err != nil {
		return nil
	}
	// Pre-resolve Subnet → Vpc so we only enqueue the relevant NWIFs.
	var subnets juneauv1alpha1.SubnetList
	if err := r.client.List(context.Background(), &subnets); err != nil {
		return nil
	}
	subnetVpc := make(map[string]string, len(subnets.Items))
	for i := range subnets.Items {
		s := &subnets.Items[i]
		subnetVpc[s.Name] = s.Spec.Vpc
	}
	var keys []string
	for i := range ifaces.Items {
		iface := &ifaces.Items[i]
		if subnetVpc[iface.Spec.Subnet] != vpc.Name {
			continue
		}
		keys = append(keys, iface.Namespace+"/"+iface.Name)
	}
	return keys
}

// FanOutSubnetToInterfaces re-enqueues every NetworkInterface in the
// given Subnet so that a Subnet status change (e.g. VNI assignment)
// flows through to the membership map.
func (r *SGMembership) FanOutSubnetToInterfaces(obj any) []string {
	subnet, ok := obj.(*juneauv1alpha1.Subnet)
	if !ok {
		return nil
	}
	var ifaces juneauv1alpha1.NetworkInterfaceList
	if err := r.client.List(context.Background(), &ifaces); err != nil {
		return nil
	}
	var keys []string
	for i := range ifaces.Items {
		iface := &ifaces.Items[i]
		if iface.Spec.Subnet != subnet.Name {
			continue
		}
		keys = append(keys, iface.Namespace+"/"+iface.Name)
	}
	return keys
}

// FanOutSGToInterfaces re-enqueues every NetworkInterface that names
// the given SecurityGroup. This is what propagates a freshly-allocated
// GroupID into the membership map.
func (r *SGMembership) FanOutSGToInterfaces(obj any) []string {
	sg, ok := obj.(*juneauv1alpha1.SecurityGroup)
	if !ok {
		return nil
	}
	var ifaces juneauv1alpha1.NetworkInterfaceList
	if err := r.client.List(context.Background(), &ifaces); err != nil {
		return nil
	}
	var keys []string
	for i := range ifaces.Items {
		iface := &ifaces.Items[i]
		for _, ref := range iface.Spec.SecurityGroups {
			if ref == sg.Name {
				keys = append(keys, iface.Namespace+"/"+iface.Name)
				break
			}
		}
	}
	return keys
}
