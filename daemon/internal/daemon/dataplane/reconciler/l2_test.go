package reconciler

import (
	"context"
	"fmt"
	"sort"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
)

// fakeL2Table stands in for l2.Table, which mints real BPF maps and so
// needs CAP_BPF. It records which VNIs exist and who is on them.
type fakeL2Table struct {
	members map[uint32]map[uint32]struct{}
}

func newFakeL2Table() *fakeL2Table {
	return &fakeL2Table{members: make(map[uint32]map[uint32]struct{})}
}

func (f *fakeL2Table) Ensure(vni uint32) error {
	if vni == 0 {
		return fmt.Errorf("vni 0 is not a network")
	}
	if _, ok := f.members[vni]; !ok {
		f.members[vni] = make(map[uint32]struct{})
	}
	return nil
}

func (f *fakeL2Table) Delete(vni uint32) error {
	delete(f.members, vni)
	return nil
}

func (f *fakeL2Table) AddMember(vni, member uint32) error {
	if err := f.Ensure(vni); err != nil {
		return err
	}
	f.members[vni][member] = struct{}{}
	return nil
}

func (f *fakeL2Table) RemoveMember(vni, member uint32) error {
	if set, ok := f.members[vni]; ok {
		delete(set, member)
	}
	return nil
}

func (f *fakeL2Table) list(vni uint32) []uint32 {
	out := make([]uint32, 0, len(f.members[vni]))
	for member := range f.members[vni] {
		out = append(out, member)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (f *fakeL2Table) has(vni uint32) bool {
	_, ok := f.members[vni]
	return ok
}

func newL2TestVpc() *juneauv1alpha1.Vpc {
	return &juneauv1alpha1.Vpc{
		ObjectMeta: metav1.ObjectMeta{Name: "vpc-a"},
		Status:     juneauv1alpha1.VpcStatus{VpcID: 11},
	}
}

func newL2TestNetwork(vni uint32) *juneauv1alpha1.L2Network {
	return &juneauv1alpha1.L2Network{
		ObjectMeta: metav1.ObjectMeta{Name: "lab-net"},
		Spec:       juneauv1alpha1.L2NetworkSpec{Vpc: "vpc-a"},
		Status:     juneauv1alpha1.L2NetworkStatus{VNI: vni},
	}
}

func newL2NetworkFixture(t *testing.T, objs ...runtime.Object) (*L2Network, *fakeBpfMap, *fakeL2Table, *fakeL2Table, *fakeL2Table) {
	t.Helper()
	cl := fake.NewClientBuilder().WithScheme(newNatTestScheme(t)).WithRuntimeObjects(objs...).Build()
	networkMap := newFakeBpfMap()
	fdb, local, remote := newFakeL2Table(), newFakeL2Table(), newFakeL2Table()
	return NewL2Network(cl, networkMap, fdb, local, remote), networkMap, fdb, local, remote
}

func TestL2NetworkClaimsItsVniAndBuildsItsTables(t *testing.T) {
	r, networkMap, fdb, local, remote := newL2NetworkFixture(t, newL2TestNetwork(4242), newL2TestVpc())

	if err := r.Reconcile(context.Background(), "lab-net"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	got, ok := networkMap.entries[bpf.PodEgressL2NetworkKey{Vni: 4242}]
	if !ok {
		t.Fatalf("l2_network_map has no entry for VNI 4242: %v", networkMap.entries)
	}
	if want := (bpf.PodEgressL2NetworkVal{VpcId: 11}); got != want {
		t.Errorf("l2_network_map value = %+v, want %+v", got, want)
	}
	for name, table := range map[string]*fakeL2Table{"fdb": fdb, "bum-local": local, "bum-remote": remote} {
		if !table.has(4242) {
			t.Errorf("%s has no table for VNI 4242", name)
		}
	}
}

// The VNI is handed out after the object exists, and everything the
// data plane keys is keyed by it. Programming anything before it lands
// would write under VNI 0, which is no network at all.
func TestL2NetworkWaitsForItsVni(t *testing.T) {
	r, networkMap, fdb, _, _ := newL2NetworkFixture(t, newL2TestNetwork(0), newL2TestVpc())

	if err := r.Reconcile(context.Background(), "lab-net"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if len(networkMap.entries) != 0 {
		t.Errorf("l2_network_map was written before the VNI landed: %v", networkMap.entries)
	}
	if fdb.has(0) {
		t.Error("a forwarding table was built under VNI 0")
	}
}

func TestL2NetworkDropsItsTablesWhenTheNetworkGoesAway(t *testing.T) {
	r, networkMap, fdb, local, remote := newL2NetworkFixture(t, newL2TestNetwork(4242), newL2TestVpc())

	if err := r.Reconcile(context.Background(), "lab-net"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if err := r.Reconcile(context.Background(), "gone"); err != nil {
		t.Fatalf("Reconcile of an unknown network: %v", err)
	}
	if err := r.client.Delete(context.Background(), newL2TestNetwork(4242)); err != nil {
		t.Fatalf("delete the network: %v", err)
	}
	if err := r.Reconcile(context.Background(), "lab-net"); err != nil {
		t.Fatalf("Reconcile after the delete: %v", err)
	}

	if len(networkMap.entries) != 0 {
		t.Errorf("l2_network_map still holds %v", networkMap.entries)
	}
	for name, table := range map[string]*fakeL2Table{"fdb": fdb, "bum-local": local, "bum-remote": remote} {
		if table.has(4242) {
			t.Errorf("%s still holds a table for a network that is gone", name)
		}
	}
}

func newL2PortFixture(t *testing.T, objs ...runtime.Object) (*L2Port, *fakeBpfMap, *fakeL2Table, *fakeL2Table) {
	t.Helper()
	cl := fake.NewClientBuilder().WithScheme(newNatTestScheme(t)).WithRuntimeObjects(objs...).Build()
	ifindexMap := newFakeBpfMap()
	local, remote := newFakeL2Table(), newFakeL2Table()
	return NewL2Port(cl, ifindexMap, local, remote, "node-a"), ifindexMap, local, remote
}

func newL2Endpoint(name, node string, ifindex int, nodeIP string) *juneauv1alpha1.NetworkEndpoint {
	endpoint := &juneauv1alpha1.NetworkEndpoint{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name},
		Spec: juneauv1alpha1.NetworkEndpointSpec{
			Kind:      juneauv1alpha1.EndpointKindPod,
			NodeName:  node,
			L2Network: "lab-net",
		},
		Status: juneauv1alpha1.NetworkEndpointStatus{NodeIP: nodeIP},
	}
	if ifindex != 0 {
		endpoint.Spec.Attachment = &juneauv1alpha1.NetworkEndpointAttachment{Ifindex: ifindex}
	}
	return endpoint
}

func TestL2PortMakesALocalEndpointAPortOfTheSegment(t *testing.T) {
	r, ifindexMap, local, remote := newL2PortFixture(t,
		newL2Endpoint("pod-a", "node-a", 7, "10.0.0.1"), newL2TestNetwork(4242))

	if err := r.Reconcile(context.Background(), "default/pod-a"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	got, ok := ifindexMap.entries[bpf.PodEgressL2IfindexKey{Ifindex: 7}]
	if !ok {
		t.Fatalf("l2_ifindex has no entry for ifindex 7: %v", ifindexMap.entries)
	}
	if want := (bpf.PodEgressL2IfindexVal{Vni: 4242}); got != want {
		t.Errorf("l2_ifindex value = %+v, want %+v", got, want)
	}
	if diff := local.list(4242); len(diff) != 1 || diff[0] != 7 {
		t.Errorf("local flood list = %v, want [7]", diff)
	}
	if len(remote.list(4242)) != 0 {
		t.Errorf("a local endpoint reached the remote flood list: %v", remote.list(4242))
	}
}

func TestL2PortMakesARemoteEndpointANodeToFloodTo(t *testing.T) {
	r, ifindexMap, local, remote := newL2PortFixture(t,
		newL2Endpoint("pod-b", "node-b", 0, "10.0.0.2"), newL2TestNetwork(4242))

	if err := r.Reconcile(context.Background(), "default/pod-b"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	// 10.0.0.2 as the host-order number bpf_tunnel_key.remote_ipv4 takes.
	if diff := remote.list(4242); len(diff) != 1 || diff[0] != 0x0a000002 {
		t.Errorf("remote flood list = %v, want [0x0a000002]", diff)
	}
	if len(local.list(4242)) != 0 {
		t.Errorf("a remote endpoint reached the local flood list: %v", local.list(4242))
	}
	if len(ifindexMap.entries) != 0 {
		t.Errorf("a remote endpoint was written to l2_ifindex: %v", ifindexMap.entries)
	}
}

// Several endpoints of one segment usually sit on the same node. The
// node has to appear on the flood list once and stay there until the
// last of them is gone, or a broadcast stops reaching the others.
func TestL2PortKeepsANodeOnTheFloodListWhileAnyEndpointIsLeft(t *testing.T) {
	first := newL2Endpoint("pod-b", "node-b", 0, "10.0.0.2")
	second := newL2Endpoint("pod-c", "node-b", 0, "10.0.0.2")
	r, _, _, remote := newL2PortFixture(t, first, second, newL2TestNetwork(4242))

	for _, key := range []string{"default/pod-b", "default/pod-c"} {
		if err := r.Reconcile(context.Background(), key); err != nil {
			t.Fatalf("Reconcile %s: %v", key, err)
		}
	}
	if err := r.client.Delete(context.Background(), first); err != nil {
		t.Fatalf("delete the first endpoint: %v", err)
	}
	if err := r.Reconcile(context.Background(), "default/pod-b"); err != nil {
		t.Fatalf("Reconcile after the delete: %v", err)
	}

	if diff := remote.list(4242); len(diff) != 1 || diff[0] != 0x0a000002 {
		t.Errorf("remote flood list = %v after one of two endpoints went away, want [0x0a000002]", diff)
	}

	if err := r.client.Delete(context.Background(), second); err != nil {
		t.Fatalf("delete the second endpoint: %v", err)
	}
	if err := r.Reconcile(context.Background(), "default/pod-c"); err != nil {
		t.Fatalf("Reconcile after the second delete: %v", err)
	}
	if diff := remote.list(4242); len(diff) != 0 {
		t.Errorf("remote flood list = %v after the last endpoint went away, want empty", diff)
	}
}

func TestL2PortFollowsAnEndpointThatMovesToAnotherNode(t *testing.T) {
	endpoint := newL2Endpoint("pod-a", "node-a", 7, "10.0.0.1")
	r, ifindexMap, local, remote := newL2PortFixture(t, endpoint, newL2TestNetwork(4242))

	if err := r.Reconcile(context.Background(), "default/pod-a"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	moved := newL2Endpoint("pod-a", "node-b", 0, "10.0.0.2")
	moved.ResourceVersion = ""
	if err := r.client.Delete(context.Background(), endpoint); err != nil {
		t.Fatalf("delete the endpoint: %v", err)
	}
	if err := r.client.Create(context.Background(), moved); err != nil {
		t.Fatalf("create the moved endpoint: %v", err)
	}
	if err := r.Reconcile(context.Background(), "default/pod-a"); err != nil {
		t.Fatalf("Reconcile after the move: %v", err)
	}

	if len(ifindexMap.entries) != 0 {
		t.Errorf("l2_ifindex still names the veth of an endpoint that left: %v", ifindexMap.entries)
	}
	if diff := local.list(4242); len(diff) != 0 {
		t.Errorf("local flood list = %v after the endpoint left, want empty", diff)
	}
	if diff := remote.list(4242); len(diff) != 1 || diff[0] != 0x0a000002 {
		t.Errorf("remote flood list = %v, want the new node", diff)
	}
}

// An endpoint on a Subnet belongs to the other data plane. Putting it
// on an L2 flood list would send frames to a port that is not on the
// segment at all.
func TestL2PortLeavesASubnetEndpointAlone(t *testing.T) {
	endpoint := newL2Endpoint("pod-a", "node-a", 7, "10.0.0.1")
	endpoint.Spec.L2Network = ""
	endpoint.Spec.Subnet = "web"
	r, ifindexMap, local, _ := newL2PortFixture(t, endpoint, newL2TestNetwork(4242))

	if err := r.Reconcile(context.Background(), "default/pod-a"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if len(ifindexMap.entries) != 0 {
		t.Errorf("a Subnet endpoint was written to l2_ifindex: %v", ifindexMap.entries)
	}
	if len(local.list(4242)) != 0 {
		t.Errorf("a Subnet endpoint reached an L2 flood list: %v", local.list(4242))
	}
}

// An endpoint whose network is gone contributes no port. Failing here
// instead would spin the work queue on an object that is never coming
// back.
func TestL2PortSkipsAnEndpointWhoseNetworkIsGone(t *testing.T) {
	r, ifindexMap, local, _ := newL2PortFixture(t, newL2Endpoint("pod-a", "node-a", 7, "10.0.0.1"))

	if err := r.Reconcile(context.Background(), "default/pod-a"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if len(ifindexMap.entries) != 0 {
		t.Errorf("l2_ifindex was written for a network that does not exist: %v", ifindexMap.entries)
	}
	if len(local.list(4242)) != 0 {
		t.Errorf("a flood list was written for a network that does not exist: %v", local.list(4242))
	}
}

// failingL2Table refuses the first AddMember, standing in for a full
// map or a kernel that said no.
type failingL2Table struct {
	*fakeL2Table
	failures int
}

func (f *failingL2Table) AddMember(vni, member uint32) error {
	if f.failures > 0 {
		f.failures--
		return fmt.Errorf("no room for member %d on vni %d", member, vni)
	}
	return f.fakeL2Table.AddMember(vni, member)
}

// A port the reconciler failed to program has to be tried again. If the
// snapshot recorded it anyway, the retry would compare the endpoint
// against what it never managed to write and decide it was done.
func TestL2PortRetriesAPortItCouldNotProgram(t *testing.T) {
	cl := fake.NewClientBuilder().WithScheme(newNatTestScheme(t)).
		WithRuntimeObjects(newL2Endpoint("pod-a", "node-a", 7, "10.0.0.1"), newL2TestNetwork(4242)).
		Build()
	local := &failingL2Table{fakeL2Table: newFakeL2Table(), failures: 1}
	r := NewL2Port(cl, newFakeBpfMap(), local, newFakeL2Table(), "node-a")

	if err := r.Reconcile(context.Background(), "default/pod-a"); err == nil {
		t.Fatal("expected the first pass to report the failed write")
	}
	if err := r.Reconcile(context.Background(), "default/pod-a"); err != nil {
		t.Fatalf("Reconcile on retry: %v", err)
	}

	if diff := local.list(4242); len(diff) != 1 || diff[0] != 7 {
		t.Errorf("local flood list = %v after the retry, want [7]", diff)
	}
}
