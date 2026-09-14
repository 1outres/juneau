package grpc

import (
	"context"
	"testing"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPodEndpointNetworkNamesTheSegmentOfTheNIC(t *testing.T) {
	elasticIP := &juneauv1alpha1.ElasticIP{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "public"},
		Spec:       juneauv1alpha1.ElasticIPSpec{ExternalNetwork: "internet"},
	}
	server := newTestCNIServer(t, elasticIP)

	for _, tc := range []struct {
		name string
		spec juneauv1alpha1.NetworkInterfaceSpec
		want juneauv1alpha1.NetworkEndpointSpec
	}{
		{
			name: "subnet",
			spec: juneauv1alpha1.NetworkInterfaceSpec{Subnet: "web"},
			want: juneauv1alpha1.NetworkEndpointSpec{Subnet: "web"},
		},
		{
			name: "l2Network",
			spec: juneauv1alpha1.NetworkInterfaceSpec{L2Network: "segment"},
			want: juneauv1alpha1.NetworkEndpointSpec{L2Network: "segment"},
		},
		{
			name: "elasticIP",
			spec: juneauv1alpha1.NetworkInterfaceSpec{ElasticIP: "public"},
			want: juneauv1alpha1.NetworkEndpointSpec{ExternalNetwork: "internet"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nwiface := &juneauv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web.eth0"},
				Spec:       tc.spec,
			}
			network, err := server.podEndpointNetwork(context.Background(), nwiface)
			if err != nil {
				t.Fatalf("podEndpointNetwork: %v", err)
			}
			var got juneauv1alpha1.NetworkEndpointSpec
			network.applyTo(&got)
			if got != tc.want {
				t.Errorf("endpoint spec = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestPodEndpointNetworkWaitsForTheElasticIP(t *testing.T) {
	server := newTestCNIServer(t)
	nwiface := &juneauv1alpha1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web.eth0"},
		Spec:       juneauv1alpha1.NetworkInterfaceSpec{ElasticIP: "public"},
	}
	if _, err := server.podEndpointNetwork(context.Background(), nwiface); err == nil {
		t.Fatal("expected an error while the ElasticIP is not in the cache")
	}
}

func TestPodEndpointNetworkReadsTheElasticIPOfTheNamespaceOfTheNIC(t *testing.T) {
	elsewhere := &juneauv1alpha1.ElasticIP{
		ObjectMeta: metav1.ObjectMeta{Namespace: "other", Name: "public"},
		Spec:       juneauv1alpha1.ElasticIPSpec{ExternalNetwork: "internet"},
	}
	server := newTestCNIServer(t, elsewhere)
	nwiface := &juneauv1alpha1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web.eth0"},
		Spec:       juneauv1alpha1.NetworkInterfaceSpec{ElasticIP: "public"},
	}
	if _, err := server.podEndpointNetwork(context.Background(), nwiface); err == nil {
		t.Fatal("an ElasticIP of another namespace must not be used")
	}
}

func TestPodEndpointNetworkRejectsANICOnNoNetwork(t *testing.T) {
	server := newTestCNIServer(t)
	nwiface := &juneauv1alpha1.NetworkInterface{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web.eth0"}}
	if _, err := server.podEndpointNetwork(context.Background(), nwiface); err == nil {
		t.Fatal("expected an error for a NIC that names no network")
	}
}
