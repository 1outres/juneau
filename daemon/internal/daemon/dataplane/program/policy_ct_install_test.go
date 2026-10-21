package program_test

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/bpftest"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/policyct"
)

// The Pod these tests protect, the peer that opens a flow to it, and
// the Subnet the Pod sits on.
const (
	policyPodAddress  = "10.70.0.5"
	policyPeerAddress = "10.70.0.9"
	policySubnetID    = 21
	policyPeerPort    = 41000
	policyPodPort     = 8080
)

// podIngressPolicy is the veth of one Pod carrying pod_ingress, on a
// Subnet with a NetworkACL attached. The ACL has no rules, so it lets
// everything in, but an attached ACL is enough for the policy stage to
// record each flow it admits in policy_ct_map.
type podIngressPolicy struct {
	objs    *bpftest.Objects
	program *ebpf.Program
	pod     bpftest.Device
}

func newPodIngressPolicy(t *testing.T, opts ...bpftest.Option) *podIngressPolicy {
	t.Helper()
	bpftest.Require(t)
	bpftest.Netns(t)

	objs := bpftest.Load(t, bpf.LoadPodIngress, opts...)
	p := &podIngressPolicy{
		objs:    objs,
		program: objs.Program(t, "tc_pod_ingress"),
		pod:     bpftest.Dummy(t, "pod1"),
	}

	if err := objs.Map(t, "ifindex_subnet").Update(
		&bpf.PodIngressIfindexSubnetKey{Ifindex: uint32(p.pod.Index)},
		&bpf.PodIngressIfindexSubnetVal{SubnetId: policySubnetID, Ipv4: networkOrderIPv4(t, policyPodAddress)},
		ebpf.UpdateAny,
	); err != nil {
		t.Fatalf("name the Subnet behind the Pod: %v", err)
	}
	if err := objs.Map(t, "subnet_map").Update(
		&bpf.PodIngressSubnetKey{SubnetId: policySubnetID},
		&bpf.PodIngressSubnetVal{VpcId: testVpcID, AclId: testACLID},
		ebpf.UpdateAny,
	); err != nil {
		t.Fatalf("declare the Subnet: %v", err)
	}
	if err := objs.Map(t, "acl_meta_map").Update(
		uint32(testACLID),
		&bpf.PodIngressAclMetaVal{},
		ebpf.UpdateAny,
	); err != nil {
		t.Fatalf("declare the ACL: %v", err)
	}
	return p
}

// openFlow hands pod_ingress the SYN of a new flow from the peer to the
// Pod and returns the verdict.
func (p *podIngressPolicy) openFlow(t *testing.T) int {
	t.Helper()
	frame := bpftest.Frame(t, bpftest.MAC(2), bpftest.MAC(1), bpftest.EtherTypeIPv4,
		bpftest.TCPv4Flags(t, policyPeerAddress, policyPodAddress, policyPeerPort, policyPodPort, bpftest.TCPFlagSYN))
	return bpftest.Run(t, p.program, frame, p.pod)
}

// forwardKey is the key pod_ingress admits the flow under: the tuple
// as it arrived, at the ingress hook. reverseKey is the other half of
// the pair: the mirrored tuple, at the egress hook.
func (p *podIngressPolicy) forwardKey(t *testing.T) bpf.PodEgressPolicyCtKey {
	t.Helper()
	return bpf.PodEgressPolicyCtKey{
		Scope: testVpcID,
		Saddr: networkOrderIPv4(t, policyPeerAddress),
		Daddr: networkOrderIPv4(t, policyPodAddress),
		Sport: bigEndianPort(policyPeerPort),
		Dport: bigEndianPort(policyPodPort),
		Proto: 6,
		Hook:  policyct.HookPodIngress,
	}
}

func (p *podIngressPolicy) reverseKey(t *testing.T) bpf.PodEgressPolicyCtKey {
	t.Helper()
	return bpf.PodEgressPolicyCtKey{
		Scope: testVpcID,
		Saddr: networkOrderIPv4(t, policyPodAddress),
		Daddr: networkOrderIPv4(t, policyPeerAddress),
		Sport: bigEndianPort(policyPodPort),
		Dport: bigEndianPort(policyPeerPort),
		Proto: 6,
		Hook:  policyct.HookPodEgress,
	}
}

func (p *podIngressPolicy) has(t *testing.T, key bpf.PodEgressPolicyCtKey) bool {
	t.Helper()
	var val bpf.PodEgressPolicyCtVal
	err := p.objs.Map(t, "policy_ct_map").Lookup(&key, &val)
	switch {
	case err == nil:
		return true
	case errors.Is(err, ebpf.ErrKeyNotExist):
		return false
	}
	t.Fatalf("look up %+v: %v", key, err)
	return false
}

// fill writes count entries that no flow of these tests uses.
func (p *podIngressPolicy) fill(t *testing.T, count int) {
	t.Helper()
	m := p.objs.Map(t, "policy_ct_map")
	for i := range count {
		key := fillerKey(i)
		if err := m.Update(&key, &bpf.PodEgressPolicyCtVal{State: 1}, ebpf.UpdateNoExist); err != nil {
			t.Fatalf("fill policy_ct_map with entry %d: %v", i, err)
		}
	}
}

// requireFull checks that policy_ct_map has no room for one more key.
func (p *podIngressPolicy) requireFull(t *testing.T) {
	t.Helper()
	key := fillerKey(policyCTSize)
	if err := p.objs.Map(t, "policy_ct_map").Update(&key, &bpf.PodEgressPolicyCtVal{}, ebpf.UpdateNoExist); err == nil {
		t.Fatal("policy_ct_map took one more key, so it was not full")
	}
}

func fillerKey(i int) bpf.PodEgressPolicyCtKey {
	return bpf.PodEgressPolicyCtKey{
		Scope: testVpcID,
		Saddr: 0x0a500000 + uint32(i),
		Daddr: 0x0a510000,
		Sport: 1000,
		Dport: 2000,
		Proto: 17,
		Hook:  policyct.HookPodEgress,
	}
}

// stat sums one slot of policy_ct_stats over every CPU.
func (p *podIngressPolicy) stat(t *testing.T, index uint32) uint64 {
	t.Helper()
	var perCPU []uint64
	if err := p.objs.Map(t, "policy_ct_stats").Lookup(index, &perCPU); err != nil {
		t.Fatalf("read slot %d of policy_ct_stats: %v", index, err)
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	return total
}

// policyCTSize is the room the tests give policy_ct_map. A small map
// fills up in a few writes.
const policyCTSize = 4

// The conntrack GC finds the other half of a pair with
// policyct.Reverse, so it has to build the same key the data plane
// wrote. This holds the Go side to what the BPF side really does.
func TestPolicyCTInstallWritesAPairThatReverseMatches(t *testing.T) {
	p := newPodIngressPolicy(t)

	if verdict := p.openFlow(t); verdict != bpftest.ActOK {
		t.Fatalf("verdict %d, want the admitted SYN delivered (%d)", verdict, bpftest.ActOK)
	}

	var (
		keys []policyct.Key
		key  policyct.Key
		val  bpf.PodEgressPolicyCtVal
	)
	iter := p.objs.Map(t, "policy_ct_map").Iterate()
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		t.Fatalf("read policy_ct_map: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("policy_ct_map holds %d keys, want the two halves of one pair: %+v", len(keys), keys)
	}
	if got := policyct.Reverse(keys[0]); got != keys[1] {
		t.Errorf("Reverse(%+v) = %+v, want the other key the data plane wrote, %+v", keys[0], got, keys[1])
	}
	if got := policyct.Reverse(keys[1]); got != keys[0] {
		t.Errorf("Reverse(%+v) = %+v, want the other key the data plane wrote, %+v", keys[1], got, keys[0])
	}
	if !p.has(t, p.forwardKey(t)) || !p.has(t, p.reverseKey(t)) {
		t.Errorf("the pair is %+v, want %+v and %+v", keys, p.forwardKey(t), p.reverseKey(t))
	}
	for _, slot := range []uint32{policyct.StatReverseInstallFailed, policyct.StatForwardInstallFailed} {
		if got := p.stat(t, slot); got != 0 {
			t.Errorf("slot %d of policy_ct_stats = %d after a write that fit, want 0", slot, got)
		}
	}
}

// With one slot left, only one half of the pair fits. It has to be the
// reverse half. A forward half on its own short-circuits every later
// packet of the flow at this hook, so the flow is never evaluated
// again and the reverse half is never written: the replies are judged
// as new flows by the rules of the other side, and the flow stays
// broken (issue #77). A reverse half on its own only lets the replies
// of a flow this hook has just admitted back in, and the next packet
// of the flow is evaluated again and writes the pair.
func TestPolicyCTInstallKeepsTheReverseHalfWhenOnlyOneFits(t *testing.T) {
	p := newPodIngressPolicy(t, bpftest.WithMaxEntries("policy_ct_map", policyCTSize))
	p.fill(t, policyCTSize-1)

	if verdict := p.openFlow(t); verdict != bpftest.ActOK {
		t.Fatalf("verdict %d, want the admitted SYN delivered (%d)", verdict, bpftest.ActOK)
	}
	if p.has(t, p.forwardKey(t)) {
		t.Error("the forward half was written although the reverse half did not fit")
	}
	if !p.has(t, p.reverseKey(t)) {
		t.Error("the reverse half was not written although it fit")
	}
	if got := p.stat(t, policyct.StatForwardInstallFailed); got != 1 {
		t.Errorf("forward install failures = %d, want 1", got)
	}
	if got := p.stat(t, policyct.StatReverseInstallFailed); got != 0 {
		t.Errorf("reverse install failures = %d, want 0", got)
	}
}

// With no room at all, neither half is written. The packet still goes
// through: the rules admitted it, and only the record of that is lost.
func TestPolicyCTInstallWritesNothingIntoAFullTable(t *testing.T) {
	p := newPodIngressPolicy(t, bpftest.WithMaxEntries("policy_ct_map", policyCTSize))
	p.fill(t, policyCTSize)
	p.requireFull(t)

	if verdict := p.openFlow(t); verdict != bpftest.ActOK {
		t.Fatalf("verdict %d, want the admitted SYN delivered (%d)", verdict, bpftest.ActOK)
	}
	if p.has(t, p.forwardKey(t)) {
		t.Error("the forward half was written into a full table")
	}
	if p.has(t, p.reverseKey(t)) {
		t.Error("the reverse half was written into a full table")
	}
	if got := p.stat(t, policyct.StatReverseInstallFailed); got != 1 {
		t.Errorf("reverse install failures = %d, want 1", got)
	}
	if got := p.stat(t, policyct.StatForwardInstallFailed); got != 0 {
		t.Errorf("forward install failures = %d, want 0: the forward half must not be tried after the reverse half failed", got)
	}
}
