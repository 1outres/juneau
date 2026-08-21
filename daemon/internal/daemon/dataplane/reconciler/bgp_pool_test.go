package reconciler

import (
	"context"
	"encoding/binary"
	"net"
	"reflect"
	"sort"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

func lpmUint32(t *testing.T, ip string) uint32 {
	t.Helper()
	parsed := net.ParseIP(ip).To4()
	if parsed == nil {
		t.Fatalf("invalid test IP %q", ip)
	}
	return binary.LittleEndian.Uint32(parsed)
}

func TestParseExternalAddressPrefix(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		wantAddr   uint32
		wantPrefix uint32
		wantCanon  string
		wantErr    bool
	}{
		{
			name:       "plain IPv4 becomes /32",
			raw:        "10.1.2.3",
			wantAddr:   lpmUint32(t, "10.1.2.3"),
			wantPrefix: 32,
			wantCanon:  "10.1.2.3/32",
		},
		{
			name:       "CIDR is canonicalized to network address",
			raw:        "10.1.2.3/24",
			wantAddr:   lpmUint32(t, "10.1.2.0"),
			wantPrefix: 24,
			wantCanon:  "10.1.2.0/24",
		},
		{
			name:       "whitespace is trimmed",
			raw:        "  10.1.2.3/24  ",
			wantAddr:   lpmUint32(t, "10.1.2.0"),
			wantPrefix: 24,
			wantCanon:  "10.1.2.0/24",
		},
		{
			name:    "empty string is rejected",
			raw:     "",
			wantErr: true,
		},
		{
			name:    "invalid IP is rejected",
			raw:     "not-an-ip",
			wantErr: true,
		},
		{
			name:    "malformed CIDR is rejected",
			raw:     "10.1.2.3/40",
			wantErr: true,
		},
		{
			name:    "IPv6 plain address is rejected",
			raw:     "fe80::1",
			wantErr: true,
		},
		{
			name:    "IPv6 CIDR is rejected",
			raw:     "fe80::/64",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, canonical, err := parseExternalAddressPrefix(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want error, got none (canonical=%q key=%+v)", canonical, key)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if canonical != tt.wantCanon {
				t.Errorf("canonical = %q, want %q", canonical, tt.wantCanon)
			}
			if key.Addr != tt.wantAddr {
				t.Errorf("key.Addr = %#x, want %#x", key.Addr, tt.wantAddr)
			}
			if key.Prefixlen != tt.wantPrefix {
				t.Errorf("key.Prefixlen = %d, want %d", key.Prefixlen, tt.wantPrefix)
			}
		})
	}
}

func newTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	utilruntime.Must(juneauv1alpha1.AddToScheme(s))
	return s
}

func TestBgpPool_BuildDesired(t *testing.T) {
	newPool := func(name string, mode juneauv1alpha1.AddressPoolAdvertiseMode, addrs ...string) *juneauv1alpha1.AddressPool {
		return &juneauv1alpha1.AddressPool{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: juneauv1alpha1.AddressPoolSpec{
				AdvertiseMode: mode,
				Addresses:     addrs,
			},
		}
	}
	newAdv := func(name string, pools ...string) *juneauv1alpha1.BGPAdvertisement {
		return &juneauv1alpha1.BGPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec:       juneauv1alpha1.BGPAdvertisementSpec{AddressPools: pools},
		}
	}

	tests := []struct {
		name         string
		objs         []runtime.Object
		wantCanon    []string
		wantWarnRegx []string
	}{
		{
			name: "referenced BGP pool emits entries, non-BGP is warned",
			objs: []runtime.Object{
				newPool("bgp", juneauv1alpha1.AddressPoolAdvertiseModeBGP, "10.1.0.0/24", "192.168.1.1"),
				newPool("arp", juneauv1alpha1.AddressPoolAdvertiseModeARP, "10.2.0.0/24"),
				newAdv("adv", "bgp", "arp"),
			},
			wantCanon:    []string{"10.1.0.0/24", "192.168.1.1/32"},
			wantWarnRegx: []string{"advertiseMode"},
		},
		{
			name: "missing pool reference is warned and skipped",
			objs: []runtime.Object{
				newAdv("adv", "ghost"),
			},
			wantCanon:    nil,
			wantWarnRegx: []string{"missing AddressPool/ghost"},
		},
		{
			name: "unreferenced BGP pool is not emitted",
			objs: []runtime.Object{
				newPool("idle", juneauv1alpha1.AddressPoolAdvertiseModeBGP, "10.3.0.0/24"),
			},
			wantCanon: nil,
		},
		{
			name: "invalid address is warned, valid siblings still emitted",
			objs: []runtime.Object{
				newPool("bgp", juneauv1alpha1.AddressPoolAdvertiseModeBGP, "bogus", "10.4.0.0/24"),
				newAdv("adv", "bgp"),
			},
			wantCanon:    []string{"10.4.0.0/24"},
			wantWarnRegx: []string{"invalid address"},
		},
		{
			name: "duplicate prefixes across pools are deduped",
			objs: []runtime.Object{
				newPool("a", juneauv1alpha1.AddressPoolAdvertiseModeBGP, "10.5.0.0/24"),
				newPool("b", juneauv1alpha1.AddressPoolAdvertiseModeBGP, "10.5.0.0/24"),
				newAdv("adv", "a", "b"),
			},
			wantCanon: []string{"10.5.0.0/24"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithRuntimeObjects(tt.objs...).Build()
			r := NewBgpPool(cl, nil)
			desired, warnings, err := r.buildDesired(context.Background())
			if err != nil {
				t.Fatalf("buildDesired: %v", err)
			}

			gotCanon := make([]string, 0, len(desired))
			for k := range desired {
				gotCanon = append(gotCanon, k)
			}
			sort.Strings(gotCanon)
			want := append([]string{}, tt.wantCanon...)
			sort.Strings(want)
			if len(gotCanon) != len(want) || (len(gotCanon) > 0 && !reflect.DeepEqual(gotCanon, want)) {
				t.Errorf("desired canonical = %v, want %v", gotCanon, want)
			}

			for _, needle := range tt.wantWarnRegx {
				found := false
				for _, w := range warnings {
					if strings.Contains(w, needle) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("want warning containing %q, got %v", needle, warnings)
				}
			}
		})
	}
}
