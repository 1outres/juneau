package program_test

import (
	"context"
	"net"
	"os"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/bpftest"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/program"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/reconciler"
)

// externalNICPinPath is where these tests pin the maps of the objects
// they load. It has to sit on bpffs and must not be the path a daemon on
// this host, or another harness in this package, is using.
const externalNICPinPath = "/sys/fs/bpf/juneau-external-nic"

// The ExternalNetwork the NICs in these tests carry their ElasticIPs on.
const (
	testExternalNetwork   = "internet"
	testExternalNetworkID = 4250
	thisNode              = "node-a"
)

// externalNode is one node as the data plane of a NIC that carries an
// ElasticIP directly sees it. Every program is loaded under one pin path,
// so the maps are one kernel object the way they are on a node, and every
// map entry is written by the reconciler that writes it on a node.
type externalNode struct {
	podEgress  *program.PodEgress
	podIngress *program.PodIngress
	client     client.Client
}

// externalNIC is one NIC on the ExternalNetwork, and the device that
// stands in for the host side of its veth.
type externalNIC struct {
	name      string
	elasticIP string
	podMAC    net.HardwareAddr
	hostMAC   net.HardwareAddr
	veth      bpftest.Device
}

func newExternalNode(t *testing.T) *externalNode {
	t.Helper()
	bpftest.Require(t)
	bpftest.Netns(t)

	if err := os.RemoveAll(externalNICPinPath); err != nil {
		t.Fatalf("clear the pin path: %v", err)
	}
	if err := os.Mkdir(externalNICPinPath, 0o700); err != nil {
		t.Skipf("cannot pin under bpffs: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(externalNICPinPath) })

	podEgress, err := program.NewPodEgress(externalNICPinPath, 0)
	if err != nil {
		t.Fatalf("load pod_egress: %+v", err)
	}
	t.Cleanup(func() { _ = podEgress.Close() })

	podIngress, err := program.NewPodIngress(externalNICPinPath)
	if err != nil {
		t.Fatalf("load pod_ingress: %+v", err)
	}
	t.Cleanup(func() { _ = podIngress.Close() })

	scheme := runtime.NewScheme()
	if err := juneauv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("build the scheme: %v", err)
	}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(
		&juneauv1alpha1.ExternalNetwork{
			ObjectMeta: metav1.ObjectMeta{Name: testExternalNetwork},
			Status:     juneauv1alpha1.ExternalNetworkStatus{NetworkID: testExternalNetworkID},
		},
	).Build()

	return &externalNode{podEgress: podEgress, podIngress: podIngress, client: cl}
}

// addLocalNIC builds the host side of a NIC's veth on this node and
// publishes the NetworkEndpoint the CNI publishes for it.
func (n *externalNode) addLocalNIC(t *testing.T, name, elasticIP string, podMAC, hostMAC net.HardwareAddr) externalNIC {
	t.Helper()
	nic := externalNIC{
		name:      name,
		elasticIP: elasticIP,
		podMAC:    podMAC,
		hostMAC:   hostMAC,
		veth:      bpftest.Dummy(t, name),
	}
	endpoint := externalEndpoint(nic, thisNode)
	endpoint.Spec.Attachment = &juneauv1alpha1.NetworkEndpointAttachment{
		Ifindex:        nic.veth.Index,
		HostMACAddress: hostMAC.String(),
	}
	n.publish(t, endpoint)

	if err := reconciler.NewPodIface(n.client, n.podEgress, thisNode).Reconcile(context.Background(), endpointKey(endpoint)); err != nil {
		t.Fatalf("name the veth of %s: %v", name, err)
	}
	return nic
}

func (n *externalNode) publish(t *testing.T, endpoint *juneauv1alpha1.NetworkEndpoint) {
	t.Helper()
	if err := n.client.Create(context.Background(), endpoint); err != nil {
		t.Fatalf("publish the endpoint %s: %v", endpoint.Name, err)
	}
}

func externalEndpoint(nic externalNIC, nodeName string) *juneauv1alpha1.NetworkEndpoint {
	return &juneauv1alpha1.NetworkEndpoint{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: nic.name + ".eth0"},
		Spec: juneauv1alpha1.NetworkEndpointSpec{
			Kind:            juneauv1alpha1.EndpointKindPod,
			NodeName:        nodeName,
			ExternalNetwork: testExternalNetwork,
			Address:         nic.elasticIP + "/32",
			MACAddress:      nic.podMAC.String(),
			PodRef:          &juneauv1alpha1.NetworkEndpointPodReference{Name: nic.name, Interface: "eth0", UID: "uid-" + nic.name},
		},
	}
}

func endpointKey(endpoint *juneauv1alpha1.NetworkEndpoint) string {
	return endpoint.Namespace + "/" + endpoint.Name
}
