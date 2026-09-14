package controller

import (
	"net/netip"
	"reflect"
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

func TestBuildElasticIPPodRouting(t *testing.T) {
	cases := []struct {
		name       string
		ifName     string
		address    string
		wantRoutes []juneauv1alpha1.NetworkRoute
		wantRules  []juneauv1alpha1.NetworkRoutingRule
		wantErr    bool
	}{
		{
			name:    "the primary NIC keeps its onLink default route in the main table",
			ifName:  juneauv1alpha1.PodPrimaryInterfaceName,
			address: "203.0.113.10",
			wantRoutes: []juneauv1alpha1.NetworkRoute{
				{Dst: "0.0.0.0/0", GW: juneauv1alpha1.PodElasticIPGateway, OnLink: true},
			},
		},
		{
			name:    "an extra NIC gets a table of its own and a rule from its address",
			ifName:  "ext0",
			address: "203.0.113.10",
			wantRoutes: []juneauv1alpha1.NetworkRoute{
				{Dst: "0.0.0.0/0", GW: juneauv1alpha1.PodElasticIPGateway, OnLink: true, Table: 3405803786},
			},
			wantRules: []juneauv1alpha1.NetworkRoutingRule{
				{From: "203.0.113.10/32", Table: 3405803786, Priority: juneauv1alpha1.PodElasticIPRulePriority},
			},
		},
		{
			name:    "an address Linux cannot turn into a table is an error",
			ifName:  "ext0",
			address: "0.0.0.7",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			routes, rules, err := buildElasticIPPodRouting(tc.ifName, netip.MustParseAddr(tc.address))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("got routes %+v and rules %+v, want an error", routes, rules)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(routes, tc.wantRoutes) {
				t.Fatalf("routes = %+v, want %+v", routes, tc.wantRoutes)
			}
			if !reflect.DeepEqual(rules, tc.wantRules) {
				t.Fatalf("rules = %+v, want %+v", rules, tc.wantRules)
			}
		})
	}
}
