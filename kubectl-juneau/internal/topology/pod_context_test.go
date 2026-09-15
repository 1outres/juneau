package topology

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

func TestBuildInterfaceContextReadsTheElasticIPANicCarries(t *testing.T) {
	elasticIP := &juneauv1alpha1.ElasticIP{
		ObjectMeta: metav1.ObjectMeta{Name: "web-eip", Namespace: "shop"},
		Status: juneauv1alpha1.ElasticIPStatus{
			Address: "203.0.113.10",
			Attachment: &juneauv1alpha1.ElasticIPStatusAttachment{
				Kind: juneauv1alpha1.ElasticIPStatusAttachmentKindNetworkInterface,
				Name: "web-0.eth0",
			},
		},
	}
	view := &stubView{elasticIPs: map[string]*juneauv1alpha1.ElasticIP{"shop/web-eip": elasticIP}}
	nic := &juneauv1alpha1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0.eth0", Namespace: "shop"},
		Spec:       juneauv1alpha1.NetworkInterfaceSpec{ElasticIP: "web-eip"},
	}

	ic, err := buildInterfaceContext(context.Background(), view, nic)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ic.DirectElasticIP != elasticIP {
		t.Fatalf("DirectElasticIP = %+v, want the ElasticIP the NIC names", ic.DirectElasticIP)
	}
	if ic.ElasticIP != nil {
		t.Fatalf("ElasticIP = %+v, want no NAT use on a NIC that carries one", ic.ElasticIP)
	}
}

func TestBuildInterfaceContextReadsTheElasticIPAttachmentOfANic(t *testing.T) {
	view := &stubView{elasticIPAttachments: []juneauv1alpha1.ElasticIPAttachment{{
		ObjectMeta: metav1.ObjectMeta{Name: "web-nat", Namespace: "shop"},
		Spec: juneauv1alpha1.ElasticIPAttachmentSpec{
			ElasticIPRef: juneauv1alpha1.ElasticIPAttachmentElasticIPRef{Name: "web-eip"},
			TargetRef:    juneauv1alpha1.ElasticIPAttachmentTargetRef{NetworkInterfaceName: "web-0.eth0"},
		},
		Status: juneauv1alpha1.ElasticIPAttachmentStatus{ElasticIP: "203.0.113.11", Phase: juneauv1alpha1.ElasticIPAttachmentPhaseAttached},
	}}}
	nic := &juneauv1alpha1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0.eth0", Namespace: "shop"},
	}

	ic, err := buildInterfaceContext(context.Background(), view, nic)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ic.DirectElasticIP != nil {
		t.Fatalf("DirectElasticIP = %+v, want none", ic.DirectElasticIP)
	}
	want := ElasticIPSummary{AttachmentName: "web-nat", ElasticIPName: "web-eip", Address: "203.0.113.11", Phase: juneauv1alpha1.ElasticIPAttachmentPhaseAttached}
	if ic.ElasticIP == nil || *ic.ElasticIP != want {
		t.Fatalf("ElasticIP = %+v, want %+v", ic.ElasticIP, want)
	}
}
