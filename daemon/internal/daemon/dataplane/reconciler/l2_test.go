package reconciler

import (
	"context"
	"fmt"
	"sort"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/l2"
)

// fakeL2Table stands in for l2.Table, which mints real BPF maps and so
// needs CAP_BPF. It records which VNIs exist and what is in them.
type fakeL2Table struct {
	entries map[uint32]map[any]any
}

func newFakeL2Table() *fakeL2Table {
	return &fakeL2Table{entries: make(map[uint32]map[any]any)}
}

func (f *fakeL2Table) Ensure(vni uint32) error {
	if vni == 0 {
		return fmt.Errorf("vni 0 is not a network")
	}
	if _, ok := f.entries[vni]; !ok {
		f.entries[vni] = make(map[any]any)
	}
	return nil
}

func (f *fakeL2Table) Delete(vni uint32) error {
	delete(f.entries, vni)
	return nil
}

func (f *fakeL2Table) Put(vni uint32, key, value any) error {
	if err := f.Ensure(vni); err != nil {
		return err
	}
	f.entries[vni][indirectValue(key)] = indirectValue(value)
	return nil
}

func (f *fakeL2Table) Remove(vni uint32, key any) error {
	if set, ok := f.entries[vni]; ok {
		delete(set, indirectValue(key))
	}
	return nil
}

func (f *fakeL2Table) PutIfAbsent(vni uint32, key, value any) error {
	if err := f.Ensure(vni); err != nil {
		return err
	}
	if _, held := f.entries[vni][indirectValue(key)]; held {
		return nil
	}
	f.entries[vni][indirectValue(key)] = indirectValue(value)
	return nil
}

func (f *fakeL2Table) RemoveIfEqual(vni uint32, key, value any) error {
	set, ok := f.entries[vni]
	if !ok {
		return nil
	}
	if current, held := set[indirectValue(key)]; !held || current != indirectValue(value) {
		return nil
	}
	delete(set, indirectValue(key))
	return nil
}

func (f *fakeL2Table) AddMember(vni, member uint32) error {
	return f.Put(vni, member, l2.PortFlagPresent)
}

func (f *fakeL2Table) RemoveMember(vni, member uint32) error {
	return f.Remove(vni, member)
}

// list is the flood-list members of a VNI, which are the entries keyed
// by a bare ifindex or VTEP address.
func (f *fakeL2Table) list(vni uint32) []uint32 {
	out := make([]uint32, 0, len(f.entries[vni]))
	for key := range f.entries[vni] {
		member, ok := key.(uint32)
		if !ok {
			continue
		}
		out = append(out, member)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (f *fakeL2Table) value(vni uint32, key any) (any, bool) {
	stored, ok := f.entries[vni][indirectValue(key)]
	return stored, ok
}

func (f *fakeL2Table) has(vni uint32) bool {
	_, ok := f.entries[vni]
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

// fakeL2Tables is one segment's tables as the reconciler tests hold
// them: the same set L2NetworkTables names, kept as fakes so the
// assertions can read what was written into each.
type fakeL2Tables struct {
	fdb       *fakeL2Table
	bumLocal  *fakeL2Table
	bumRemote *fakeL2Table
	arp       *fakeL2Table
	arpProbe  *fakeL2Table
}

func (f fakeL2Tables) byName() map[string]*fakeL2Table {
	return map[string]*fakeL2Table{
		"fdb":        f.fdb,
		"bum-local":  f.bumLocal,
		"bum-remote": f.bumRemote,
		"arp":        f.arp,
		"arp-probe":  f.arpProbe,
	}
}

func newL2NetworkFixture(t *testing.T, objs ...runtime.Object) (*L2Network, *fakeBpfMap, fakeL2Tables) {
	t.Helper()
	cl := fake.NewClientBuilder().WithScheme(newNatTestScheme(t)).WithRuntimeObjects(objs...).Build()
	networkMap := newFakeBpfMap()
	tables := fakeL2Tables{
		fdb:       newFakeL2Table(),
		bumLocal:  newFakeL2Table(),
		bumRemote: newFakeL2Table(),
		arp:       newFakeL2Table(),
		arpProbe:  newFakeL2Table(),
	}
	reconciler := NewL2Network(cl, networkMap, L2NetworkTables{
		Fdb:       tables.fdb,
		BumLocal:  tables.bumLocal,
		BumRemote: tables.bumRemote,
		Arp:       tables.arp,
		ArpProbe:  tables.arpProbe,
	})
	return reconciler, networkMap, tables
}

func TestL2NetworkClaimsItsVniAndBuildsItsTables(t *testing.T) {
	r, networkMap, tables := newL2NetworkFixture(t, newL2TestNetwork(4242), newL2TestVpc())

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
	for name, table := range tables.byName() {
		if !table.has(4242) {
			t.Errorf("%s has no table for VNI 4242", name)
		}
	}
}

// The VNI is handed out after the object exists, and everything the
// data plane keys is keyed by it. Programming anything before it lands
// would write under VNI 0, which is no network at all.
func TestL2NetworkWaitsForItsVni(t *testing.T) {
	r, networkMap, tables := newL2NetworkFixture(t, newL2TestNetwork(0), newL2TestVpc())

	if err := r.Reconcile(context.Background(), "lab-net"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if len(networkMap.entries) != 0 {
		t.Errorf("l2_network_map was written before the VNI landed: %v", networkMap.entries)
	}
	if tables.fdb.has(0) {
		t.Error("a forwarding table was built under VNI 0")
	}
}

func TestL2NetworkDropsItsTablesWhenTheNetworkGoesAway(t *testing.T) {
	r, networkMap, tables := newL2NetworkFixture(t, newL2TestNetwork(4242), newL2TestVpc())

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
	for name, table := range tables.byName() {
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

// failingL2Table refuses the first few writes, standing in for a full
// map or a kernel that said no.
type failingL2Table struct {
	*fakeL2Table
	addFailures    int
	removeFailures int
}

func (f *failingL2Table) AddMember(vni, member uint32) error {
	if f.addFailures > 0 {
		f.addFailures--
		return fmt.Errorf("no room for member %d on vni %d", member, vni)
	}
	return f.fakeL2Table.AddMember(vni, member)
}

func (f *failingL2Table) RemoveMember(vni, member uint32) error {
	if f.removeFailures > 0 {
		f.removeFailures--
		return fmt.Errorf("cannot remove member %d from vni %d", member, vni)
	}
	return f.fakeL2Table.RemoveMember(vni, member)
}

// A port the reconciler failed to program has to be tried again. If the
// snapshot recorded it anyway, the retry would compare the endpoint
// against what it never managed to write and decide it was done.
func TestL2PortRetriesAPortItCouldNotProgram(t *testing.T) {
	cl := fake.NewClientBuilder().WithScheme(newNatTestScheme(t)).
		WithRuntimeObjects(newL2Endpoint("pod-a", "node-a", 7, "10.0.0.1"), newL2TestNetwork(4242)).
		Build()
	local := &failingL2Table{fakeL2Table: newFakeL2Table(), addFailures: 1}
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

// A node two endpoints share must not leave the flood list because the
// first of them failed to come off it. The failed release is retried,
// and until it lands the endpoint still counts as holding the port.
func TestL2PortKeepsACountAfterAFailedRelease(t *testing.T) {
	first := newL2Endpoint("pod-b", "node-b", 0, "10.0.0.2")
	second := newL2Endpoint("pod-c", "node-b", 0, "10.0.0.2")
	cl := fake.NewClientBuilder().WithScheme(newNatTestScheme(t)).
		WithRuntimeObjects(first, second, newL2TestNetwork(4242)).
		Build()
	remote := &failingL2Table{fakeL2Table: newFakeL2Table()}
	r := NewL2Port(cl, newFakeBpfMap(), newFakeL2Table(), remote, "node-a")

	for _, key := range []string{"default/pod-b", "default/pod-c"} {
		if err := r.Reconcile(context.Background(), key); err != nil {
			t.Fatalf("Reconcile %s: %v", key, err)
		}
	}

	remote.removeFailures = 1
	if err := cl.Delete(context.Background(), first); err != nil {
		t.Fatalf("delete the first endpoint: %v", err)
	}
	if err := cl.Delete(context.Background(), second); err != nil {
		t.Fatalf("delete the second endpoint: %v", err)
	}
	// pod-b comes off the count, pod-c takes it to zero and the write
	// fails there.
	if err := r.Reconcile(context.Background(), "default/pod-b"); err != nil {
		t.Fatalf("Reconcile after the first delete: %v", err)
	}
	if err := r.Reconcile(context.Background(), "default/pod-c"); err == nil {
		t.Fatal("expected the failed write to be reported")
	}
	if diff := remote.list(4242); len(diff) != 1 {
		t.Errorf("remote flood list = %v while the release is unfinished, want the node still on it", diff)
	}

	if err := r.Reconcile(context.Background(), "default/pod-c"); err != nil {
		t.Fatalf("Reconcile on retry: %v", err)
	}
	if diff := remote.list(4242); len(diff) != 0 {
		t.Errorf("remote flood list = %v after the retry, want empty", diff)
	}
}

// A network deleted and made again under the same VNI leaves the
// endpoint on it recorded as programmed into tables that no longer
// exist. The two events reach the queue as one key, so the reconcile
// that runs sees no change at all: the only thing that puts the port
// back is writing the entries every pass.
func TestL2PortRebuildsTheTablesOfARecreatedNetwork(t *testing.T) {
	r, ifindexMap, local, _ := newL2PortFixture(t,
		newL2Endpoint("pod-a", "node-a", 7, "10.0.0.1"), newL2TestNetwork(4242))

	if err := r.Reconcile(context.Background(), "default/pod-a"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	// What the L2Network reconciler does when the network goes away.
	if err := local.Delete(4242); err != nil {
		t.Fatalf("drop the flood list: %v", err)
	}
	ifindexMap.entries = map[any]any{}

	if err := r.Reconcile(context.Background(), "default/pod-a"); err != nil {
		t.Fatalf("Reconcile after the network came back: %v", err)
	}

	if diff := local.list(4242); len(diff) != 1 || diff[0] != 7 {
		t.Errorf("local flood list = %v, want the port back on it", diff)
	}
	if _, ok := ifindexMap.entries[bpf.PodEgressL2IfindexKey{Ifindex: 7}]; !ok {
		t.Errorf("l2_ifindex is empty after the network came back: %v", ifindexMap.entries)
	}
}

// A relist that misses a delete hands the fan-out a tombstone instead
// of the object. Dropping it would leave every endpoint of the network
// recorded as programmed into tables that are gone.
func TestL2PortFansOutFromATombstone(t *testing.T) {
	r, _, _, _ := newL2PortFixture(t,
		newL2Endpoint("pod-a", "node-a", 7, "10.0.0.1"), newL2TestNetwork(4242))

	keys := r.FanOutL2NetworkToEndpoints(toolscache.DeletedFinalStateUnknown{
		Key: "lab-net",
		Obj: newL2TestNetwork(4242),
	})

	if len(keys) != 1 || keys[0] != "default/pod-a" {
		t.Errorf("fan-out returned %v, want [default/pod-a]", keys)
	}
}

// The kernel hands veth indexes out again. An endpoint that leaves
// must not take the l2_ifindex entry of the endpoint that took its
// index over, or l2_egress drops every frame that endpoint sends.
func TestL2PortLeavesAVethAnotherEndpointTookOver(t *testing.T) {
	leaving := newL2Endpoint("pod-a", "node-a", 7, "10.0.0.1")
	arriving := newL2Endpoint("pod-b", "node-a", 7, "10.0.0.1")
	arriving.Spec.L2Network = "other-net"

	other := newL2TestNetwork(4242)
	other.Name = "other-net"
	other.Status.VNI = 9999

	cl := fake.NewClientBuilder().WithScheme(newNatTestScheme(t)).
		WithRuntimeObjects(leaving, arriving, newL2TestNetwork(4242), other).
		Build()
	ifindexMap := newFakeBpfMap()
	r := NewL2Port(cl, ifindexMap, newFakeL2Table(), newFakeL2Table(), "node-a")

	if err := r.Reconcile(context.Background(), "default/pod-a"); err != nil {
		t.Fatalf("Reconcile pod-a: %v", err)
	}
	// pod-b comes up on the same veth index, on another network.
	if err := r.Reconcile(context.Background(), "default/pod-b"); err != nil {
		t.Fatalf("Reconcile pod-b: %v", err)
	}
	if err := cl.Delete(context.Background(), leaving); err != nil {
		t.Fatalf("delete pod-a: %v", err)
	}
	if err := r.Reconcile(context.Background(), "default/pod-a"); err != nil {
		t.Fatalf("Reconcile after the delete: %v", err)
	}

	got, ok := ifindexMap.entries[bpf.PodEgressL2IfindexKey{Ifindex: 7}]
	if !ok {
		t.Fatalf("l2_ifindex lost the entry of the endpoint that took the veth over: %v", ifindexMap.entries)
	}
	if want := (bpf.PodEgressL2IfindexVal{Vni: 9999}); got != want {
		t.Errorf("l2_ifindex value = %+v, want %+v", got, want)
	}
}
