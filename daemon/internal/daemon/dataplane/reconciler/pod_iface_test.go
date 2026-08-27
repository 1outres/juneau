package reconciler

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
)

func newPodIfaceEndpoint(address string) *juneauv1alpha1.NetworkEndpoint {
	return &juneauv1alpha1.NetworkEndpoint{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "pod-a"},
		Spec: juneauv1alpha1.NetworkEndpointSpec{
			Kind:     juneauv1alpha1.EndpointKindPod,
			NodeName: "node-a",
			Subnet:   "subnet-a",
			Address:  address,
			Attachment: &juneauv1alpha1.NetworkEndpointAttachment{
				Ifindex:        7,
				HostMACAddress: "02:00:00:00:00:01",
			},
		},
	}
}

func newPodIfaceSubnet() *juneauv1alpha1.Subnet {
	return &juneauv1alpha1.Subnet{
		ObjectMeta: metav1.ObjectMeta{Name: "subnet-a"},
		Status:     juneauv1alpha1.SubnetStatus{VNI: 42},
	}
}

func newPodIfaceFixture(t *testing.T, objs ...runtime.Object) (*PodIface, *fakeBpfMap, *fakeBpfMap) {
	t.Helper()
	cl := fake.NewClientBuilder().WithScheme(newNatTestScheme(t)).WithRuntimeObjects(objs...).Build()
	subnetMap := newFakeBpfMap()
	hostMACMap := newFakeBpfMap()
	r := &PodIface{
		client:         cl,
		ifindexSubnet:  subnetMap,
		ifindexHostMac: hostMACMap,
		nodeName:       "node-a",
		snapshots:      make(map[string]uint32),
	}
	return r, subnetMap, hostMACMap
}

func TestPodIfaceWritesPodAddressInNetworkByteOrder(t *testing.T) {
	r, subnetMap, _ := newPodIfaceFixture(t, newPodIfaceEndpoint("10.16.0.5/24"), newPodIfaceSubnet())

	if err := r.Reconcile(context.Background(), "default/pod-a"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	got, ok := subnetMap.entries[bpf.PodEgressIfindexSubnetKey{Ifindex: 7}]
	if !ok {
		t.Fatalf("ifindex_subnet has no entry for ifindex 7: %v", subnetMap.entries)
	}
	want := bpf.PodEgressIfindexSubnetVal{SubnetId: 42, Ipv4: 0x0500100a}
	if got != want {
		t.Errorf("ifindex_subnet value = %+v, want %+v", got, want)
	}
}

func TestPodIfaceAcceptsBareAddress(t *testing.T) {
	r, subnetMap, _ := newPodIfaceFixture(t, newPodIfaceEndpoint("10.16.0.5"), newPodIfaceSubnet())

	if err := r.Reconcile(context.Background(), "default/pod-a"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	got, ok := subnetMap.entries[bpf.PodEgressIfindexSubnetKey{Ifindex: 7}]
	if !ok {
		t.Fatalf("ifindex_subnet has no entry for ifindex 7: %v", subnetMap.entries)
	}
	want := bpf.PodEgressIfindexSubnetVal{SubnetId: 42, Ipv4: 0x0500100a}
	if got != want {
		t.Errorf("ifindex_subnet value = %+v, want %+v", got, want)
	}
}

// A NIC the data plane cannot name by address cannot be checked against
// sg_membership_map, so writing the entry anyway would open the very
// hole the policy stage is meant to close.
func TestPodIfaceRejectsEndpointWithoutUsableAddress(t *testing.T) {
	cases := []struct {
		name    string
		address string
	}{
		{name: "empty", address: ""},
		{name: "malformed", address: "not-an-address"},
		{name: "ipv6", address: "fd00::5/64"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, subnetMap, hostMACMap := newPodIfaceFixture(t, newPodIfaceEndpoint(tc.address), newPodIfaceSubnet())

			if err := r.Reconcile(context.Background(), "default/pod-a"); err == nil {
				t.Fatal("Reconcile succeeded, want an error")
			}
			if len(subnetMap.entries) != 0 {
				t.Errorf("ifindex_subnet was written: %v", subnetMap.entries)
			}
			if len(hostMACMap.entries) != 0 {
				t.Errorf("ifindex_host_mac was written: %v", hostMACMap.entries)
			}
		})
	}
}

func TestEndpointAddressToBE(t *testing.T) {
	cases := []struct {
		name    string
		address string
		want    uint32
		wantErr bool
	}{
		{name: "cidr", address: "10.16.0.5/24", want: 0x0500100a},
		{name: "cidr keeps the host part", address: "192.168.1.130/25", want: 0x8201a8c0},
		{name: "bare", address: "10.16.0.5", want: 0x0500100a},
		{name: "empty", address: "", wantErr: true},
		{name: "malformed", address: "10.16.0.5/", wantErr: true},
		{name: "ipv6", address: "fd00::5/64", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := endpointAddressToBE(tc.address)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("endpointAddressToBE(%q) = %#x, want an error", tc.address, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("endpointAddressToBE(%q): %v", tc.address, err)
			}
			if got != tc.want {
				t.Errorf("endpointAddressToBE(%q) = %#x, want %#x", tc.address, got, tc.want)
			}
		})
	}
}
