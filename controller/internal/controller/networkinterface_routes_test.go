package controller

import (
	"testing"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

func TestBuildPodRoutes(t *testing.T) {
	cases := []struct {
		name    string
		ifName  string
		gateway string
		want    []juneauv1alpha1.NetworkRoute
	}{
		{
			name:    "the primary NIC carries the default route",
			ifName:  juneauv1alpha1.PodPrimaryInterfaceName,
			gateway: "10.16.0.1",
			want:    []juneauv1alpha1.NetworkRoute{{Dst: "0.0.0.0/0", GW: "10.16.0.1"}},
		},
		{
			name:    "an extra NIC gets no default route",
			ifName:  "eth1",
			gateway: "10.17.0.1",
			want:    nil,
		},
		{
			name:    "a subnet without a gateway routes nowhere",
			ifName:  juneauv1alpha1.PodPrimaryInterfaceName,
			gateway: "",
			want:    nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := buildPodRoutes(tc.ifName, tc.gateway)
			if len(got) != len(tc.want) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %+v, want %+v", got, tc.want)
				}
			}
		})
	}
}
