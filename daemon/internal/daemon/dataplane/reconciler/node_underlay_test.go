package reconciler

import (
	"encoding/binary"
	"net"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// beUint32 encodes an IPv4 address the way the BPF map key must be
// laid out on a little-endian host so it byte-compares equal to
// iph->daddr. Kept private to the test so a regression that swaps the
// convert helper's byte-order is caught here as well.
func beUint32(t *testing.T, ip string) uint32 {
	t.Helper()
	parsed := net.ParseIP(ip).To4()
	if parsed == nil {
		t.Fatalf("invalid test IP %q", ip)
	}
	return binary.LittleEndian.Uint32(parsed)
}

func TestBuildNodeUnderlayDesired(t *testing.T) {
	tests := []struct {
		name string
		node *corev1.Node
		want []uint32
	}{
		{
			name: "single InternalIPv4 is included",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "yakumo01"},
				Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeInternalIP, Address: "192.168.116.1"},
				}},
			},
			want: []uint32{beUint32(t, "192.168.116.1")},
		},
		{
			name: "ExternalIP and Hostname are skipped",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "yakumo01"},
				Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeInternalIP, Address: "192.168.116.1"},
					{Type: corev1.NodeExternalIP, Address: "203.0.113.4"},
					{Type: corev1.NodeHostName, Address: "yakumo01.example.com"},
				}},
			},
			want: []uint32{beUint32(t, "192.168.116.1")},
		},
		{
			name: "InternalIPv6 is skipped (map is IPv4-only)",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "yakumo01"},
				Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeInternalIP, Address: "fd00::1"},
					{Type: corev1.NodeInternalIP, Address: "192.168.116.1"},
				}},
			},
			want: []uint32{beUint32(t, "192.168.116.1")},
		},
		{
			name: "multiple InternalIPv4 are returned sorted and deduped",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "yakumo01"},
				Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeInternalIP, Address: "192.168.116.11"},
					{Type: corev1.NodeInternalIP, Address: "192.168.116.1"},
					{Type: corev1.NodeInternalIP, Address: "192.168.116.1"},
				}},
			},
			want: sortedUint32([]uint32{
				beUint32(t, "192.168.116.1"),
				beUint32(t, "192.168.116.11"),
			}),
		},
		{
			name: "unparseable Address is silently skipped",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "yakumo01"},
				Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeInternalIP, Address: "not-an-ip"},
					{Type: corev1.NodeInternalIP, Address: "192.168.116.1"},
				}},
			},
			want: []uint32{beUint32(t, "192.168.116.1")},
		},
		{
			name: "Node with no addresses returns empty",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "yakumo01"},
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildNodeUnderlayDesired(tt.node)
			if err != nil {
				t.Fatalf("buildNodeUnderlayDesired: %v", err)
			}
			if len(got) == 0 && len(tt.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDiffUint32Sets(t *testing.T) {
	tests := []struct {
		name             string
		prev, desired    []uint32
		wantAdd, wantDel []uint32
	}{
		{
			name:    "add all when prev empty",
			desired: []uint32{1, 2, 3},
			wantAdd: []uint32{1, 2, 3},
		},
		{
			name:    "del all when desired empty",
			prev:    []uint32{1, 2, 3},
			wantDel: []uint32{1, 2, 3},
		},
		{
			name:    "no diff when equal",
			prev:    []uint32{1, 2, 3},
			desired: []uint32{1, 2, 3},
		},
		{
			name:    "partial replacement",
			prev:    []uint32{1, 2, 3},
			desired: []uint32{2, 3, 4},
			wantAdd: []uint32{4},
			wantDel: []uint32{1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAdd, gotDel := diffUint32Sets(tt.prev, tt.desired)
			if !equalUint32Slices(gotAdd, tt.wantAdd) {
				t.Errorf("add: got %v, want %v", gotAdd, tt.wantAdd)
			}
			if !equalUint32Slices(gotDel, tt.wantDel) {
				t.Errorf("del: got %v, want %v", gotDel, tt.wantDel)
			}
		})
	}
}

func sortedUint32(xs []uint32) []uint32 {
	out := append([]uint32(nil), xs...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

func equalUint32Slices(a, b []uint32) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}
