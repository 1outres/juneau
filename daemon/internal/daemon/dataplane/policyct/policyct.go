// Package policyct mirrors the parts of daemon/bpf/policy_ct.h that
// user space needs: how the two halves of an admission pair up, and
// where policy_ct_stats counts the halves that could not be written.
// The data plane writes these keys and counters, and the conntrack GC
// reads them, so the two sides have to agree.
package policyct

import bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"

// Key is a policy_ct_map key.
type Key = bpf.PodEgressPolicyCtKey

// Hook values mirror POLICY_HOOK_* in daemon/bpf/maps.h.
const (
	HookPodEgress  uint8 = 1
	HookPodIngress uint8 = 2
)

// The slots of policy_ct_stats, mirroring POLICY_CT_STAT_* in
// daemon/bpf/maps.h.
const (
	// StatReverseInstallFailed counts the admissions that wrote neither
	// half: the reverse half did not fit, so the forward half was not
	// tried.
	StatReverseInstallFailed uint32 = 0
	// StatForwardInstallFailed counts the admissions that wrote the
	// reverse half but not the forward half.
	StatForwardInstallFailed uint32 = 1
)

// Reverse returns the other half of the pair key belongs to: the same
// flow, as the enforcement point on the other side sees it. It builds
// the key the way policy_ct_reverse_key does. Reverse(Reverse(k)) is k
// for every key the data plane writes.
func Reverse(key Key) Key {
	return Key{
		Epoch: key.Epoch,
		Scope: key.Scope,
		Saddr: key.Daddr,
		Daddr: key.Saddr,
		Sport: key.Dport,
		Dport: key.Sport,
		Proto: key.Proto,
		Hook:  peerHook(key.Hook),
	}
}

// peerHook mirrors policy_ct_peer_hook.
func peerHook(hook uint8) uint8 {
	if hook == HookPodEgress {
		return HookPodIngress
	}
	return HookPodEgress
}
