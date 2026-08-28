package describe

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/kubectl-juneau/internal/output"
	"github.com/1outres/juneau/kubectl-juneau/internal/topology"
)

func renderNIC(t *testing.T, ic *topology.InterfaceContext) string {
	t.Helper()
	root := output.NewNode("Pod  default/lab")
	appendInterfaceNode(root, ic)
	var out strings.Builder
	if err := output.WriteTree(&out, root); err != nil {
		t.Fatalf("write the tree: %v", err)
	}
	return out.String()
}

func TestDescribeNamesTheL2NetworkANicJoined(t *testing.T) {
	rendered := renderNIC(t, &topology.InterfaceContext{
		NetworkInterface: &juneauv1alpha1.NetworkInterface{
			ObjectMeta: metav1.ObjectMeta{Name: "lab.eth1"},
			Spec:       juneauv1alpha1.NetworkInterfaceSpec{L2Network: "lab-net"},
		},
		L2Network: &juneauv1alpha1.L2Network{
			ObjectMeta: metav1.ObjectMeta{Name: "lab-net"},
			Spec:       juneauv1alpha1.L2NetworkSpec{Vpc: "vpc-a"},
			Status:     juneauv1alpha1.L2NetworkStatus{VNI: 4242, MTU: 1450},
		},
		Vpc: &juneauv1alpha1.Vpc{
			ObjectMeta: metav1.ObjectMeta{Name: "vpc-a"},
			Status:     juneauv1alpha1.VpcStatus{VpcID: 11},
		},
	})

	for _, want := range []string{"L2Network  lab-net", "vni: 4242", "mtu: 1450", "Vpc  vpc-a"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("the tree does not mention %q:\n%s", want, rendered)
		}
	}
}

func TestDescribeSaysWhenTheL2NetworkOfANicIsGone(t *testing.T) {
	rendered := renderNIC(t, &topology.InterfaceContext{
		NetworkInterface: &juneauv1alpha1.NetworkInterface{
			ObjectMeta: metav1.ObjectMeta{Name: "lab.eth1"},
			Spec:       juneauv1alpha1.NetworkInterfaceSpec{L2Network: "lab-net"},
		},
	})

	if want := "L2Network  lab-net  (not found)"; !strings.Contains(rendered, want) {
		t.Errorf("the tree does not mention %q:\n%s", want, rendered)
	}
}

// A NIC on a Subnet has no L2Network line at all: an empty one would
// read as a segment that could not be resolved.
func TestDescribeLeavesTheL2NetworkLineOutForASubnetNic(t *testing.T) {
	rendered := renderNIC(t, &topology.InterfaceContext{
		NetworkInterface: &juneauv1alpha1.NetworkInterface{
			ObjectMeta: metav1.ObjectMeta{Name: "lab.eth0"},
			Spec:       juneauv1alpha1.NetworkInterfaceSpec{Subnet: "web"},
		},
	})

	if strings.Contains(rendered, "L2Network") {
		t.Errorf("the tree mentions an L2Network for a Subnet NIC:\n%s", rendered)
	}
}
