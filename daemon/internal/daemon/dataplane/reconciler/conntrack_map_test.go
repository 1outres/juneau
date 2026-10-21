package reconciler

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/ctstate"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/internal/mapsweep"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/policyct"
)

// policyMaps are policy_ct_map and policy_ct_stats with the layout and
// the size of the real ones. The sweep reads the maps back with
// syscalls, so only real maps show what it does with them.
type policyMaps struct {
	ct    *ebpf.Map
	stats *ebpf.Map
}

func newPolicyMaps(t *testing.T) policyMaps {
	t.Helper()
	spec, err := bpf.LoadPodEgress()
	if err != nil {
		t.Fatalf("read the pod_egress object: %v", err)
	}
	build := func(name string) *ebpf.Map {
		mapSpec := spec.Maps[name].Copy()
		mapSpec.Pinning = ebpf.PinNone
		m, err := ebpf.NewMap(mapSpec)
		if err != nil {
			t.Skipf("ebpf.NewMap unavailable on this host: %v", err)
		}
		t.Cleanup(func() { _ = m.Close() })
		return m
	}
	return policyMaps{ct: build("policy_ct_map"), stats: build("policy_ct_stats")}
}

// sweeper is the policy table the GC builds over these maps. Each call
// of its sweep is one pass.
func (p policyMaps) sweeper(epoch uint32) ctTable {
	return policyTable(p.ct, p.stats, fixedEpoch(epoch))
}

// flowKey is the key of flow i at the egress hook. Every i gets a key
// of its own.
func flowKey(epoch uint32, i int) policyCTKey {
	return policyCTKey{
		Epoch: epoch,
		Scope: 7,
		Saddr: 0x0a000000 + uint32(i),
		Daddr: 0x0b000001,
		Sport: 40000,
		Dport: 80,
		Proto: ctstate.ProtoTCP,
		Hook:  policyct.HookPodEgress,
	}
}

func seenAt(state uint8, lastSeenNs uint64) policyCTVal {
	return policyCTVal{State: state, LastSeenNs: lastSeenNs}
}

func writeAll(t *testing.T, m *ebpf.Map, keys []policyCTKey, vals []policyCTVal) {
	t.Helper()
	if n, err := m.BatchUpdate(keys, vals, nil); err != nil || n != len(keys) {
		t.Fatalf("write %d entries: wrote %d: %v", len(keys), n, err)
	}
}

func readAll(t *testing.T, m *ebpf.Map) map[policyCTKey]policyCTVal {
	t.Helper()
	entries, err := mapsweep.Snapshot[policyCTKey, policyCTVal](m)
	if err != nil {
		t.Fatalf("read the map back: %v", err)
	}
	out := make(map[policyCTKey]policyCTVal, len(entries))
	for _, e := range entries {
		out[e.Key] = e.Value
	}
	return out
}

// The shape issue #77 was found in: a full policy_ct_map, mostly
// entries of policy epochs that are long gone. The epoch is part of the
// key, so nothing but this sweep can remove them, and one pass has to
// remove all of them.
func TestPolicyCTSweepClearsAFullTableOfOldEpochs(t *testing.T) {
	maps := newPolicyMaps(t)

	const (
		now     = uint64(10 * time.Hour)
		current = uint32(9)
	)
	size := int(maps.ct.MaxEntries())
	old := size * 64 / 100

	keys := make([]policyCTKey, size)
	vals := make([]policyCTVal, size)
	for i := range size {
		epoch := current
		if i < old {
			epoch = current - 1 - uint32(i%3)
		}
		keys[i] = flowKey(epoch, i)
		vals[i] = seenAt(ctstate.StateEstablished, now-uint64(time.Minute))
	}
	writeAll(t, maps.ct, keys, vals)

	report := maps.sweeper(current).sweep(now)

	left := readAll(t, maps.ct)
	oldLeft := 0
	for key := range left {
		if key.Epoch != current {
			oldLeft++
		}
	}
	if oldLeft != 0 {
		t.Errorf("%d of %d entries of old epochs survived the pass", oldLeft, old)
	}
	if got, want := len(left)-oldLeft, size-old; got != want {
		t.Errorf("%d entries of the current epoch survived the pass, want all %d", got, want)
	}
	if report.Err != nil {
		t.Errorf("the pass failed: %v", report.Err)
	}
	if report.Stats.Read != size || report.Stats.Removed[reasonStaleEpoch] != old || report.Stats.Removed[reasonExpired] != 0 {
		t.Errorf("stats = %+v, want %d read and %d removed for their epoch", report.Stats, size, old)
	}
	if report.Stats.Occupancy() < mapsweep.NearlyFull {
		t.Errorf("occupancy = %v of a full table", report.Stats.Occupancy())
	}
}

// The data plane keeps writing and deleting while the sweep runs. That
// must not cut the pass short: every entry of an old epoch that was
// there from the start, and that nothing else deleted, is gone after
// one pass.
func TestPolicyCTSweepFinishesWhileTheDataPlaneWrites(t *testing.T) {
	maps := newPolicyMaps(t)
	m := maps.ct

	const (
		now     = uint64(10 * time.Hour)
		current = uint32(9)
	)
	size := int(m.MaxEntries())
	old := size / 2

	oldKeys := make([]policyCTKey, old)
	vals := make([]policyCTVal, old)
	for i := range old {
		oldKeys[i] = flowKey(current-1, i)
		vals[i] = seenAt(ctstate.StateEstablished, now)
	}
	writeAll(t, m, oldKeys, vals)

	// The writer acts like the data plane. It opens fresh flows of the
	// current epoch and closes them again a little later, so it writes
	// keys the sweep has not reached yet and deletes keys the sweep has
	// already read. Now and then it also closes one of the old entries.
	// It keeps at most liveFlows of its own flows open, so the map
	// never fills up.
	const liveFlows = 1024
	var (
		wg      sync.WaitGroup
		stop    = make(chan struct{})
		started = make(chan struct{})
		quit    = make(chan struct{})
		ops     atomic.Int64
		written []policyCTKey
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(quit)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if i == liveFlows {
				close(started)
			}
			key := flowKey(current, size+i)
			key.Hook = policyct.HookPodIngress
			if err := m.Update(&key, seenAt(ctstate.StateEstablished, now), ebpf.UpdateNoExist); err != nil {
				t.Errorf("open flow %d: %v", i, err)
				return
			}
			written = append(written, key)
			if i >= liveFlows {
				if err := m.Delete(&written[i-liveFlows]); err != nil {
					t.Errorf("close flow %d: %v", i-liveFlows, err)
					return
				}
			}
			if i%5 == 0 && i/5 < old {
				if err := m.Delete(&oldKeys[i/5]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
					t.Errorf("close an old flow: %v", err)
					return
				}
			}
			ops.Add(1)
		}
	}()
	select {
	case <-started:
	case <-quit:
		t.FailNow()
	}

	sweeper := maps.sweeper(current)
	before := ops.Load()
	report := sweeper.sweep(now)
	during := ops.Load() - before
	close(stop)
	wg.Wait()

	if during == 0 {
		t.Fatal("the writer did nothing while the sweep ran, so the test proves nothing")
	}
	left := readAll(t, m)
	survivors := 0
	for _, key := range oldKeys {
		if _, ok := left[key]; ok {
			survivors++
		}
	}
	if survivors != 0 {
		t.Errorf("%d entries of an old epoch survived the pass", survivors)
	}
	open := written[max(0, len(written)-liveFlows):]
	for _, key := range open {
		if _, ok := left[key]; !ok {
			t.Errorf("the pass removed a fresh flow of the current epoch: %+v", key)
			break
		}
	}
	if report.Err != nil {
		t.Errorf("the pass failed: %v", report.Err)
	}
	t.Logf("the writer did %d steps while the sweep ran", during)
}

// Both halves of a pair carry the same flow, and losing one half is
// what breaks it: the forward half alone short-circuits the flow at the
// hook that admitted it, so the reverse half is never written again and
// every reply is judged as a new flow. The sweep therefore removes a
// pair only when both halves are idle, and removes them together.
func TestPolicyCTSweepJudgesAPairAsOne(t *testing.T) {
	maps := newPolicyMaps(t)

	const (
		now     = uint64(10 * time.Hour)
		current = uint32(9)
	)
	fresh := seenAt(ctstate.StateEstablished, now-uint64(time.Second))
	idle := seenAt(ctstate.StateEstablished, now-uint64(time.Second)-uint64(ctstate.TTLUDP))

	// One-way UDP: the sender keeps the forward half fresh, the replies
	// stopped and their half went idle.
	oneWay := flowKey(current, 1)
	oneWay.Proto = ctstate.ProtoUDP
	// The same, with the replies still coming and the sender quiet.
	quietSender := flowKey(current, 2)
	quietSender.Proto = ctstate.ProtoUDP
	// Nothing moves in either direction any more.
	dead := flowKey(current, 3)
	dead.Proto = ctstate.ProtoUDP
	// A half whose partner is already gone.
	orphan := flowKey(current, 4)
	orphan.Proto = ctstate.ProtoUDP

	keys := []policyCTKey{
		oneWay, reverseOf(oneWay),
		quietSender, reverseOf(quietSender),
		dead, reverseOf(dead),
		orphan,
	}
	vals := []policyCTVal{
		fresh, idle,
		idle, fresh,
		idle, idle,
		idle,
	}
	writeAll(t, maps.ct, keys, vals)

	report := maps.sweeper(current).sweep(now)

	left := readAll(t, maps.ct)
	for _, tc := range []struct {
		name string
		key  policyCTKey
		want bool
	}{
		{"one-way flow, forward half", oneWay, true},
		{"one-way flow, idle reverse half", reverseOf(oneWay), true},
		{"quiet sender, idle forward half", quietSender, true},
		{"quiet sender, reverse half", reverseOf(quietSender), true},
		{"dead flow, forward half", dead, false},
		{"dead flow, reverse half", reverseOf(dead), false},
		{"idle half without a partner", orphan, false},
	} {
		if _, ok := left[tc.key]; ok != tc.want {
			t.Errorf("%s: present=%v, want %v", tc.name, ok, tc.want)
		}
	}
	if report.Err != nil {
		t.Errorf("the pass failed: %v", report.Err)
	}
	if got := report.Stats.Removed[reasonExpired]; got != 3 {
		t.Errorf("removed %d idle keys, want the 3 of the dead pair and the orphan", got)
	}
}

// reverseOf is written out by hand here rather than taken from the
// code under test, so the test does not agree with a wrong mirror.
func reverseOf(k policyCTKey) policyCTKey {
	r := k
	r.Saddr, r.Daddr = k.Daddr, k.Saddr
	r.Sport, r.Dport = k.Dport, k.Sport
	if k.Hook == policyct.HookPodEgress {
		r.Hook = policyct.HookPodIngress
	} else {
		r.Hook = policyct.HookPodEgress
	}
	return r
}

// The data plane counts the pairs it could not write in policy_ct_stats,
// one count per CPU. Each pass reports how much the totals grew since
// the pass before, and a growth makes the report a warning.
func TestPolicyCTSweepReportsTheGrowthOfInstallFailures(t *testing.T) {
	maps := newPolicyMaps(t)
	sweeper := maps.sweeper(1)

	addFailures := func(slot uint32, onEachCPU uint64) {
		t.Helper()
		var perCPU []uint64
		if err := maps.stats.Lookup(slot, &perCPU); err != nil {
			t.Fatalf("read slot %d: %v", slot, err)
		}
		for i := range perCPU {
			perCPU[i] += onEachCPU
		}
		if err := maps.stats.Update(slot, perCPU, ebpf.UpdateAny); err != nil {
			t.Fatalf("write slot %d: %v", slot, err)
		}
	}
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("count the CPUs: %v", err)
	}
	failures := func(report mapsweep.Report) (reverse, forward any) {
		t.Helper()
		for i := 0; i+1 < len(report.Fields); i += 2 {
			switch report.Fields[i] {
			case "reverseInstallFailures":
				reverse = report.Fields[i+1]
			case "forwardInstallFailures":
				forward = report.Fields[i+1]
			}
		}
		return reverse, forward
	}

	addFailures(policyct.StatReverseInstallFailed, 2)
	addFailures(policyct.StatForwardInstallFailed, 1)
	first := sweeper.sweep(0)
	if reverse, forward := failures(first); reverse != uint64(2*cpus) || forward != uint64(cpus) {
		t.Errorf("first pass reports reverse=%v forward=%v, want %d and %d", reverse, forward, 2*cpus, cpus)
	}
	if len(first.Warnings) == 0 {
		t.Error("a pass that saw install failures is not a warning")
	}

	quiet := sweeper.sweep(0)
	if reverse, forward := failures(quiet); reverse != uint64(0) || forward != uint64(0) {
		t.Errorf("a pass with no new failures reports reverse=%v forward=%v, want 0 and 0", reverse, forward)
	}
	if len(quiet.Warnings) != 0 {
		t.Errorf("a pass with no new failures warns: %v", quiet.Warnings)
	}

	addFailures(policyct.StatForwardInstallFailed, 1)
	again := sweeper.sweep(0)
	if reverse, forward := failures(again); reverse != uint64(0) || forward != uint64(cpus) {
		t.Errorf("third pass reports reverse=%v forward=%v, want 0 and %d", reverse, forward, cpus)
	}
	if len(again.Warnings) == 0 {
		t.Error("a pass that saw new install failures is not a warning")
	}
}
