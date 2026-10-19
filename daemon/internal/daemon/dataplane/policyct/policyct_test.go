package policyct

import "testing"

func TestReverseMirrorsTheTupleAtThePeerHook(t *testing.T) {
	key := Key{
		Epoch: 3,
		Scope: 7,
		Saddr: 0x0a000001,
		Daddr: 0x0a000002,
		Sport: 40000,
		Dport: 80,
		Proto: 6,
		Hook:  HookPodEgress,
	}
	want := Key{
		Epoch: 3,
		Scope: 7,
		Saddr: 0x0a000002,
		Daddr: 0x0a000001,
		Sport: 80,
		Dport: 40000,
		Proto: 6,
		Hook:  HookPodIngress,
	}
	if got := Reverse(key); got != want {
		t.Errorf("Reverse(%+v) = %+v, want %+v", key, got, want)
	}
}

// The GC finds the other half of a pair by reversing a key, so going
// there and back has to land on the key it started from.
func TestReverseOfTheReverseIsTheKey(t *testing.T) {
	for _, hook := range []uint8{HookPodEgress, HookPodIngress} {
		key := Key{Epoch: 1, Scope: 2, Saddr: 3, Daddr: 4, Sport: 5, Dport: 6, Proto: 17, Hook: hook}
		if got := Reverse(Reverse(key)); got != key {
			t.Errorf("hook %d: Reverse(Reverse(%+v)) = %+v", hook, key, got)
		}
	}
}

// policy_ct_reverse_key builds the key with a designated initializer,
// so the padding of the reverse key is always zero.
func TestReverseLeavesThePaddingZero(t *testing.T) {
	key := Key{Hook: HookPodEgress, Pad: [2]uint8{1, 2}}
	if got := Reverse(key).Pad; got != [2]uint8{} {
		t.Errorf("padding = %v, want zero", got)
	}
}
