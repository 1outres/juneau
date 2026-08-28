package topology

import (
	"context"
	"sync"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// kubeView is the production View implementation. It is intentionally
// stateful (per-instance memoisation cache) but short-lived: each
// command run constructs a fresh kubeView, runs one or two resolvers,
// and discards it. Caching across invocations is not a goal.
//
// Listing strategy: the API server has no field-selector indexes for
// most CRD fields we care about (spec.vpc, spec.subnet, …), so we
// list-once per kind and filter client-side. For an envelope-sized
// cluster (≤ a few thousand objects) this is fast and correct; if the
// kubectl plugin ever has to scale to ten-thousand-Pod tenants the
// kubeView is the right place to add server-side index probing.
type kubeView struct {
	cl client.Client

	mu              sync.Mutex
	vpcCache        map[string]*juneauv1alpha1.Vpc
	subnetCache     map[string]*juneauv1alpha1.Subnet
	l2NetworkCache  map[string]*juneauv1alpha1.L2Network
	routeTableCache map[string]*juneauv1alpha1.RouteTable
	sgCache         map[string]*juneauv1alpha1.SecurityGroup
	aclCache        map[string]*juneauv1alpha1.NetworkACL
	natGwCache      map[string]*juneauv1alpha1.NATGateway

	// Bulk listings memoised once per command invocation.
	allSubnetsOnce        sync.Once
	allSubnets            []juneauv1alpha1.Subnet
	allSubnetsErr         error
	allRouteTablesOnce    sync.Once
	allRouteTables        []juneauv1alpha1.RouteTable
	allRouteTablesErr     error
	allSecurityGroupsOnce sync.Once
	allSecurityGroups     []juneauv1alpha1.SecurityGroup
	allSecurityGroupsErr  error
	allNetworkACLsOnce    sync.Once
	allNetworkACLs        []juneauv1alpha1.NetworkACL
	allNetworkACLsErr     error
	allNATGatewaysOnce    sync.Once
	allNATGateways        []juneauv1alpha1.NATGateway
	allNATGatewaysErr     error
	allEIPAttachOnce      sync.Once
	allEIPAttachments     []juneauv1alpha1.ElasticIPAttachment
	allEIPAttachErr       error
}

// NewKubeView wires the production View on top of a controller-runtime
// client. The client must already have corev1, discoveryv1 and
// juneauv1alpha1 registered on its scheme — factory.kubeFactory does
// this.
func NewKubeView(cl client.Client) View {
	return &kubeView{
		cl:              cl,
		vpcCache:        map[string]*juneauv1alpha1.Vpc{},
		subnetCache:     map[string]*juneauv1alpha1.Subnet{},
		l2NetworkCache:  map[string]*juneauv1alpha1.L2Network{},
		routeTableCache: map[string]*juneauv1alpha1.RouteTable{},
		sgCache:         map[string]*juneauv1alpha1.SecurityGroup{},
		aclCache:        map[string]*juneauv1alpha1.NetworkACL{},
		natGwCache:      map[string]*juneauv1alpha1.NATGateway{},
	}
}

// ---- corev1 / discoveryv1 ------------------------------------------

func (v *kubeView) Pod(ctx context.Context, ns, name string) (*corev1.Pod, error) {
	var p corev1.Pod
	if err := v.cl.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &p); err != nil {
		return nil, ignoreNotFound(err)
	}
	return &p, nil
}

func (v *kubeView) Service(ctx context.Context, ns, name string) (*corev1.Service, error) {
	var s corev1.Service
	if err := v.cl.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &s); err != nil {
		return nil, ignoreNotFound(err)
	}
	return &s, nil
}

func (v *kubeView) EndpointSlicesForService(ctx context.Context, ns, name string) ([]discoveryv1.EndpointSlice, error) {
	var list discoveryv1.EndpointSliceList
	sel := labels.SelectorFromSet(labels.Set{discoveryv1.LabelServiceName: name})
	if err := v.cl.List(ctx, &list, client.InNamespace(ns), client.MatchingLabelsSelector{Selector: sel}); err != nil {
		return nil, err
	}
	return list.Items, nil
}

func (v *kubeView) ServiceLoadBalancer(ctx context.Context, ns, name string) (*juneauv1alpha1.ServiceLoadBalancer, error) {
	var slb juneauv1alpha1.ServiceLoadBalancer
	if err := v.cl.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &slb); err != nil {
		return nil, ignoreNotFound(err)
	}
	return &slb, nil
}

func (v *kubeView) ExternalNetwork(ctx context.Context, name string) (*juneauv1alpha1.ExternalNetwork, error) {
	var en juneauv1alpha1.ExternalNetwork
	if err := v.cl.Get(ctx, client.ObjectKey{Name: name}, &en); err != nil {
		return nil, ignoreNotFound(err)
	}
	return &en, nil
}

// ---- Single-object (memoised) --------------------------------------

func (v *kubeView) Vpc(ctx context.Context, name string) (*juneauv1alpha1.Vpc, error) {
	v.mu.Lock()
	if cached, ok := v.vpcCache[name]; ok {
		v.mu.Unlock()
		return cached, nil
	}
	v.mu.Unlock()

	var obj juneauv1alpha1.Vpc
	if err := v.cl.Get(ctx, client.ObjectKey{Name: name}, &obj); err != nil {
		if apierrors.IsNotFound(err) {
			v.mu.Lock()
			v.vpcCache[name] = nil
			v.mu.Unlock()
			return nil, nil
		}
		return nil, err
	}
	v.mu.Lock()
	v.vpcCache[name] = &obj
	v.mu.Unlock()
	return &obj, nil
}

func (v *kubeView) Subnet(ctx context.Context, name string) (*juneauv1alpha1.Subnet, error) {
	v.mu.Lock()
	if cached, ok := v.subnetCache[name]; ok {
		v.mu.Unlock()
		return cached, nil
	}
	v.mu.Unlock()

	var obj juneauv1alpha1.Subnet
	if err := v.cl.Get(ctx, client.ObjectKey{Name: name}, &obj); err != nil {
		if apierrors.IsNotFound(err) {
			v.mu.Lock()
			v.subnetCache[name] = nil
			v.mu.Unlock()
			return nil, nil
		}
		return nil, err
	}
	v.mu.Lock()
	v.subnetCache[name] = &obj
	v.mu.Unlock()
	return &obj, nil
}

func (v *kubeView) L2Network(ctx context.Context, name string) (*juneauv1alpha1.L2Network, error) {
	v.mu.Lock()
	if cached, ok := v.l2NetworkCache[name]; ok {
		v.mu.Unlock()
		return cached, nil
	}
	v.mu.Unlock()

	var obj juneauv1alpha1.L2Network
	if err := v.cl.Get(ctx, client.ObjectKey{Name: name}, &obj); err != nil {
		if apierrors.IsNotFound(err) {
			v.mu.Lock()
			v.l2NetworkCache[name] = nil
			v.mu.Unlock()
			return nil, nil
		}
		return nil, err
	}
	v.mu.Lock()
	v.l2NetworkCache[name] = &obj
	v.mu.Unlock()
	return &obj, nil
}

func (v *kubeView) RouteTable(ctx context.Context, name string) (*juneauv1alpha1.RouteTable, error) {
	v.mu.Lock()
	if cached, ok := v.routeTableCache[name]; ok {
		v.mu.Unlock()
		return cached, nil
	}
	v.mu.Unlock()

	var obj juneauv1alpha1.RouteTable
	if err := v.cl.Get(ctx, client.ObjectKey{Name: name}, &obj); err != nil {
		if apierrors.IsNotFound(err) {
			v.mu.Lock()
			v.routeTableCache[name] = nil
			v.mu.Unlock()
			return nil, nil
		}
		return nil, err
	}
	v.mu.Lock()
	v.routeTableCache[name] = &obj
	v.mu.Unlock()
	return &obj, nil
}

func (v *kubeView) NetworkInterface(ctx context.Context, ns, name string) (*juneauv1alpha1.NetworkInterface, error) {
	var obj juneauv1alpha1.NetworkInterface
	if err := v.cl.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &obj); err != nil {
		return nil, ignoreNotFound(err)
	}
	return &obj, nil
}

func (v *kubeView) SecurityGroup(ctx context.Context, name string) (*juneauv1alpha1.SecurityGroup, error) {
	v.mu.Lock()
	if cached, ok := v.sgCache[name]; ok {
		v.mu.Unlock()
		return cached, nil
	}
	v.mu.Unlock()

	var obj juneauv1alpha1.SecurityGroup
	if err := v.cl.Get(ctx, client.ObjectKey{Name: name}, &obj); err != nil {
		if apierrors.IsNotFound(err) {
			v.mu.Lock()
			v.sgCache[name] = nil
			v.mu.Unlock()
			return nil, nil
		}
		return nil, err
	}
	v.mu.Lock()
	v.sgCache[name] = &obj
	v.mu.Unlock()
	return &obj, nil
}

func (v *kubeView) NetworkACL(ctx context.Context, name string) (*juneauv1alpha1.NetworkACL, error) {
	v.mu.Lock()
	if cached, ok := v.aclCache[name]; ok {
		v.mu.Unlock()
		return cached, nil
	}
	v.mu.Unlock()

	var obj juneauv1alpha1.NetworkACL
	if err := v.cl.Get(ctx, client.ObjectKey{Name: name}, &obj); err != nil {
		if apierrors.IsNotFound(err) {
			v.mu.Lock()
			v.aclCache[name] = nil
			v.mu.Unlock()
			return nil, nil
		}
		return nil, err
	}
	v.mu.Lock()
	v.aclCache[name] = &obj
	v.mu.Unlock()
	return &obj, nil
}

func (v *kubeView) NATGateway(ctx context.Context, name string) (*juneauv1alpha1.NATGateway, error) {
	v.mu.Lock()
	if cached, ok := v.natGwCache[name]; ok {
		v.mu.Unlock()
		return cached, nil
	}
	v.mu.Unlock()

	var obj juneauv1alpha1.NATGateway
	if err := v.cl.Get(ctx, client.ObjectKey{Name: name}, &obj); err != nil {
		if apierrors.IsNotFound(err) {
			v.mu.Lock()
			v.natGwCache[name] = nil
			v.mu.Unlock()
			return nil, nil
		}
		return nil, err
	}
	v.mu.Lock()
	v.natGwCache[name] = &obj
	v.mu.Unlock()
	return &obj, nil
}

// ---- Listings (memoised) -------------------------------------------

func (v *kubeView) listAllSubnets(ctx context.Context) ([]juneauv1alpha1.Subnet, error) {
	v.allSubnetsOnce.Do(func() {
		var list juneauv1alpha1.SubnetList
		if err := v.cl.List(ctx, &list); err != nil {
			v.allSubnetsErr = err
			return
		}
		v.allSubnets = list.Items
	})
	return v.allSubnets, v.allSubnetsErr
}

func (v *kubeView) listAllRouteTables(ctx context.Context) ([]juneauv1alpha1.RouteTable, error) {
	v.allRouteTablesOnce.Do(func() {
		var list juneauv1alpha1.RouteTableList
		if err := v.cl.List(ctx, &list); err != nil {
			v.allRouteTablesErr = err
			return
		}
		v.allRouteTables = list.Items
	})
	return v.allRouteTables, v.allRouteTablesErr
}

func (v *kubeView) listAllSecurityGroups(ctx context.Context) ([]juneauv1alpha1.SecurityGroup, error) {
	v.allSecurityGroupsOnce.Do(func() {
		var list juneauv1alpha1.SecurityGroupList
		if err := v.cl.List(ctx, &list); err != nil {
			v.allSecurityGroupsErr = err
			return
		}
		v.allSecurityGroups = list.Items
	})
	return v.allSecurityGroups, v.allSecurityGroupsErr
}

func (v *kubeView) listAllNetworkACLs(ctx context.Context) ([]juneauv1alpha1.NetworkACL, error) {
	v.allNetworkACLsOnce.Do(func() {
		var list juneauv1alpha1.NetworkACLList
		if err := v.cl.List(ctx, &list); err != nil {
			v.allNetworkACLsErr = err
			return
		}
		v.allNetworkACLs = list.Items
	})
	return v.allNetworkACLs, v.allNetworkACLsErr
}

func (v *kubeView) listAllNATGateways(ctx context.Context) ([]juneauv1alpha1.NATGateway, error) {
	v.allNATGatewaysOnce.Do(func() {
		var list juneauv1alpha1.NATGatewayList
		if err := v.cl.List(ctx, &list); err != nil {
			v.allNATGatewaysErr = err
			return
		}
		v.allNATGateways = list.Items
	})
	return v.allNATGateways, v.allNATGatewaysErr
}

func (v *kubeView) listAllEIPAttachments(ctx context.Context) ([]juneauv1alpha1.ElasticIPAttachment, error) {
	v.allEIPAttachOnce.Do(func() {
		var list juneauv1alpha1.ElasticIPAttachmentList
		if err := v.cl.List(ctx, &list); err != nil {
			v.allEIPAttachErr = err
			return
		}
		v.allEIPAttachments = list.Items
	})
	return v.allEIPAttachments, v.allEIPAttachErr
}

func (v *kubeView) SubnetsByVpc(ctx context.Context, vpc string) ([]juneauv1alpha1.Subnet, error) {
	all, err := v.listAllSubnets(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]juneauv1alpha1.Subnet, 0, len(all))
	for i := range all {
		if all[i].Spec.Vpc == vpc {
			out = append(out, all[i])
		}
	}
	return out, nil
}

func (v *kubeView) RouteTablesByVpc(ctx context.Context, vpc string) ([]juneauv1alpha1.RouteTable, error) {
	all, err := v.listAllRouteTables(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]juneauv1alpha1.RouteTable, 0, len(all))
	for i := range all {
		if all[i].Spec.Vpc == vpc {
			out = append(out, all[i])
		}
	}
	return out, nil
}

func (v *kubeView) SecurityGroupsByVpc(ctx context.Context, vpc string) ([]juneauv1alpha1.SecurityGroup, error) {
	all, err := v.listAllSecurityGroups(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]juneauv1alpha1.SecurityGroup, 0, len(all))
	for i := range all {
		if all[i].Spec.Vpc == vpc {
			out = append(out, all[i])
		}
	}
	return out, nil
}

func (v *kubeView) NetworkACLsByVpc(ctx context.Context, vpc string) ([]juneauv1alpha1.NetworkACL, error) {
	all, err := v.listAllNetworkACLs(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]juneauv1alpha1.NetworkACL, 0, len(all))
	for i := range all {
		if all[i].Spec.Vpc == vpc {
			out = append(out, all[i])
		}
	}
	return out, nil
}

func (v *kubeView) NATGatewaysByVpc(ctx context.Context, vpc string) ([]juneauv1alpha1.NATGateway, error) {
	all, err := v.listAllNATGateways(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]juneauv1alpha1.NATGateway, 0, len(all))
	for i := range all {
		if all[i].Spec.Vpc == vpc {
			out = append(out, all[i])
		}
	}
	return out, nil
}

func (v *kubeView) NetworkInterfacesByPod(ctx context.Context, ns, name string) ([]juneauv1alpha1.NetworkInterface, error) {
	var list juneauv1alpha1.NetworkInterfaceList
	if err := v.cl.List(ctx, &list, client.InNamespace(ns)); err != nil {
		return nil, err
	}
	out := make([]juneauv1alpha1.NetworkInterface, 0, len(list.Items))
	for i := range list.Items {
		if list.Items[i].Spec.PodRef.Name == name {
			out = append(out, list.Items[i])
		}
	}
	return out, nil
}

func (v *kubeView) NetworkInterfacesBySubnet(ctx context.Context, subnet string) ([]juneauv1alpha1.NetworkInterface, error) {
	var list juneauv1alpha1.NetworkInterfaceList
	if err := v.cl.List(ctx, &list); err != nil {
		return nil, err
	}
	out := make([]juneauv1alpha1.NetworkInterface, 0, len(list.Items))
	for i := range list.Items {
		if list.Items[i].Spec.Subnet == subnet {
			out = append(out, list.Items[i])
		}
	}
	return out, nil
}

func (v *kubeView) ElasticIPAttachmentsForNIC(ctx context.Context, nicName string) ([]juneauv1alpha1.ElasticIPAttachment, error) {
	all, err := v.listAllEIPAttachments(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]juneauv1alpha1.ElasticIPAttachment, 0, len(all))
	for i := range all {
		if all[i].Spec.TargetRef.NetworkInterfaceName == nicName {
			out = append(out, all[i])
		}
	}
	return out, nil
}

func (v *kubeView) ElasticIP(ctx context.Context, name string) (*juneauv1alpha1.ElasticIP, error) {
	var obj juneauv1alpha1.ElasticIP
	if err := v.cl.Get(ctx, client.ObjectKey{Name: name}, &obj); err != nil {
		return nil, ignoreNotFound(err)
	}
	return &obj, nil
}

// ---- helpers -------------------------------------------------------

func ignoreNotFound(err error) error {
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}
