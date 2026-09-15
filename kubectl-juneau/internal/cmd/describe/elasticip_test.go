package describe

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/kubectl-juneau/internal/topology"
)

func directNIC(name, elasticIP string) *juneauv1alpha1.NetworkInterface {
	return &juneauv1alpha1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "shop"},
		Spec:       juneauv1alpha1.NetworkInterfaceSpec{ElasticIP: elasticIP},
	}
}

func directElasticIP(holder *juneauv1alpha1.ElasticIPStatusAttachment) *juneauv1alpha1.ElasticIP {
	phase := juneauv1alpha1.ElasticIPPhaseAvailable
	if holder != nil {
		phase = juneauv1alpha1.ElasticIPPhaseAttached
	}
	return &juneauv1alpha1.ElasticIP{
		ObjectMeta: metav1.ObjectMeta{Name: "web-eip", Namespace: "shop"},
		Spec:       juneauv1alpha1.ElasticIPSpec{ExternalNetwork: "internet"},
		Status:     juneauv1alpha1.ElasticIPStatus{Address: "203.0.113.10", Phase: phase, Attachment: holder},
	}
}

func TestDescribeShowsTheElasticIPANicCarries(t *testing.T) {
	rendered := renderNIC(t, &topology.InterfaceContext{
		NetworkInterface: directNIC("web-0.eth0", "web-eip"),
		DirectElasticIP: directElasticIP(&juneauv1alpha1.ElasticIPStatusAttachment{
			Kind: juneauv1alpha1.ElasticIPStatusAttachmentKindNetworkInterface,
			Name: "web-0.eth0",
		}),
	})

	want := "ElasticIP  web-eip  (direct, address: 203.0.113.10, phase: Attached, externalNetwork: internet, carried by this NIC)"
	if !strings.Contains(rendered, want) {
		t.Errorf("the tree does not mention %q:\n%s", want, rendered)
	}
}

func TestDescribeSaysWhoCarriesTheElasticIPANicWaitsFor(t *testing.T) {
	rendered := renderNIC(t, &topology.InterfaceContext{
		NetworkInterface: directNIC("web-1.eth0", "web-eip"),
		DirectElasticIP: directElasticIP(&juneauv1alpha1.ElasticIPStatusAttachment{
			Kind: juneauv1alpha1.ElasticIPStatusAttachmentKindNetworkInterface,
			Name: "web-0.eth0",
		}),
	})

	want := "(direct, address: 203.0.113.10, phase: Attached, externalNetwork: internet, carried by NetworkInterface web-0.eth0)"
	if !strings.Contains(rendered, want) {
		t.Errorf("the tree does not mention %q:\n%s", want, rendered)
	}
}

func TestDescribeSaysWhenNothingCarriesTheElasticIPANicNames(t *testing.T) {
	rendered := renderNIC(t, &topology.InterfaceContext{
		NetworkInterface: directNIC("web-1.eth0", "web-eip"),
		DirectElasticIP:  directElasticIP(nil),
	})

	want := "(direct, address: 203.0.113.10, phase: Available, externalNetwork: internet, carried by nothing yet)"
	if !strings.Contains(rendered, want) {
		t.Errorf("the tree does not mention %q:\n%s", want, rendered)
	}
}

func TestDescribeSaysWhenTheElasticIPOfANicIsGone(t *testing.T) {
	rendered := renderNIC(t, &topology.InterfaceContext{
		NetworkInterface: directNIC("web-0.eth0", "web-eip"),
	})

	want := "ElasticIP  web-eip  (direct, not found)"
	if !strings.Contains(rendered, want) {
		t.Errorf("the tree does not mention %q:\n%s", want, rendered)
	}
}

func TestDescribeShowsTheElasticIPANicUsesForNAT(t *testing.T) {
	rendered := renderNIC(t, &topology.InterfaceContext{
		NetworkInterface: &juneauv1alpha1.NetworkInterface{ObjectMeta: metav1.ObjectMeta{Name: "web-0.eth0"}},
		ElasticIP: &topology.ElasticIPSummary{
			AttachmentName: "web-nat",
			ElasticIPName:  "web-eip",
			Address:        "203.0.113.11",
			Phase:          juneauv1alpha1.ElasticIPAttachmentPhaseAttached,
		},
	})

	want := "ElasticIP  web-eip  (nat, attachment: web-nat, address: 203.0.113.11, phase: Attached)"
	if !strings.Contains(rendered, want) {
		t.Errorf("the tree does not mention %q:\n%s", want, rendered)
	}
}

func TestDescribeSaysWhenANicUsesNoElasticIP(t *testing.T) {
	rendered := renderNIC(t, &topology.InterfaceContext{
		NetworkInterface: &juneauv1alpha1.NetworkInterface{ObjectMeta: metav1.ObjectMeta{Name: "web-0.eth0"}},
	})

	if want := "ElasticIP  (none)"; !strings.Contains(rendered, want) {
		t.Errorf("the tree does not mention %q:\n%s", want, rendered)
	}
}
