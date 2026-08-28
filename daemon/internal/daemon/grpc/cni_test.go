package grpc

import (
	"strings"
	"testing"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func podInterface(ifname, address string, allocated bool) juneauv1alpha1.NetworkInterface {
	nwiface := juneauv1alpha1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web." + ifname},
		Spec: juneauv1alpha1.NetworkInterfaceSpec{
			PodRef: juneauv1alpha1.NetworkInterfacePodReference{UID: "uid-web", Name: "web", Interface: ifname},
		},
		Status: juneauv1alpha1.NetworkInterfaceStatus{Address: address},
	}
	status := metav1.ConditionFalse
	if allocated {
		status = metav1.ConditionTrue
	}
	nwiface.Status.Conditions = []metav1.Condition{{
		Type:               juneauv1alpha1.NetworkInterfaceStatusAllocated,
		Status:             status,
		Reason:             "Test",
		LastTransitionTime: metav1.Now(),
	}}
	return nwiface
}

func ifnamesOf(ifaces []*juneauv1alpha1.NetworkInterface) []string {
	out := make([]string, 0, len(ifaces))
	for _, iface := range ifaces {
		out = append(out, iface.Spec.PodRef.Interface)
	}
	return out
}

func TestOrderPodInterfacesPutsThePrimaryFirst(t *testing.T) {
	items := []juneauv1alpha1.NetworkInterface{
		podInterface("eth2", "10.16.0.5/24", true),
		podInterface("data0", "10.17.0.5/24", true),
		podInterface("eth0", "10.18.0.5/24", true),
		podInterface("eth1", "10.19.0.5/24", true),
	}
	got := ifnamesOf(orderPodInterfaces(items, "eth0"))
	want := []string{"eth0", "data0", "eth1", "eth2"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestOrderPodInterfacesWithoutThePrimary(t *testing.T) {
	items := []juneauv1alpha1.NetworkInterface{
		podInterface("eth2", "10.16.0.5/24", true),
		podInterface("eth1", "10.19.0.5/24", true),
	}
	got := ifnamesOf(orderPodInterfaces(items, "eth0"))
	want := []string{"eth1", "eth2"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestCheckPrimaryPodInterface(t *testing.T) {
	items := []juneauv1alpha1.NetworkInterface{
		podInterface("eth1", "10.19.0.5/24", true),
		podInterface("eth0", "10.18.0.5/24", true),
	}
	if err := checkPrimaryPodInterface(orderPodInterfaces(items, "eth0"), "eth0"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err := checkPrimaryPodInterface(orderPodInterfaces(items[:1], "eth0"), "eth0")
	if err == nil {
		t.Fatal("expected an error when the primary NIC is missing")
	}
	if !strings.Contains(err.Error(), "eth0") {
		t.Fatalf("error should name the missing NIC, got %v", err)
	}
}

func TestCheckPrimaryPodInterfaceWithoutAddress(t *testing.T) {
	items := []juneauv1alpha1.NetworkInterface{podInterface("eth0", "", true)}
	err := checkPrimaryPodInterface(orderPodInterfaces(items, "eth0"), "eth0")
	if err == nil {
		t.Fatal("expected an error when the primary NIC has no address")
	}
}

func TestCheckPodInterfacesAllocated(t *testing.T) {
	ready := []juneauv1alpha1.NetworkInterface{
		podInterface("eth0", "10.18.0.5/24", true),
		podInterface("eth1", "10.19.0.5/24", true),
	}
	if err := checkPodInterfacesAllocated(orderPodInterfaces(ready, "eth0")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	pending := []juneauv1alpha1.NetworkInterface{
		podInterface("eth0", "10.18.0.5/24", true),
		podInterface("eth1", "", false),
	}
	err := checkPodInterfacesAllocated(orderPodInterfaces(pending, "eth0"))
	if err == nil {
		t.Fatal("expected an error while one NIC is still being allocated")
	}
	if !strings.Contains(err.Error(), "eth1") {
		t.Fatalf("error should name the NIC that is not ready, got %v", err)
	}

}

// An L2Network without a CIDR hands out no address, and a NIC on one is
// allocated as soon as the controller says so. Holding the sandbox back
// for an address that is never coming would leave the pod in
// ContainerCreating for good.
func TestCheckPodInterfacesAllocatedAcceptsAnExtraNicWithoutAnAddress(t *testing.T) {
	addressless := []juneauv1alpha1.NetworkInterface{
		podInterface("eth0", "10.18.0.5/24", true),
		podInterface("eth1", "", true),
	}
	if err := checkPodInterfacesAllocated(orderPodInterfaces(addressless, "eth0")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVethNamesFitTheKernelLimit(t *testing.T) {
	containerID := "0123456789abcdef0123456789abcdef"
	names := []string{
		juneauv1alpha1.PodPrimaryInterfaceName,
		strings.Repeat("e", juneauv1alpha1.PodInterfaceNameMaxLen),
	}
	for _, ifName := range names {
		host := vethHostName(ifName, containerID)
		if len(host) > linkNameMaxLen {
			t.Errorf("host veth name %q is %d characters, the kernel takes %d", host, len(host), linkNameMaxLen)
		}
		if id := strings.TrimPrefix(host, ifName+"+"); len(id) < vethNameIDMinLen {
			t.Errorf("host veth name %q keeps only %d characters of the container id, want %d", host, len(id), vethNameIDMinLen)
		}
	}
	for index := 0; index < 32; index++ {
		peer := vethPeerName(index, containerID)
		if len(peer) > linkNameMaxLen {
			t.Errorf("peer veth name %q is %d characters, the kernel takes %d", peer, len(peer), linkNameMaxLen)
		}
	}
}

func TestVethHostNameKeepsTheCurrentPrimaryName(t *testing.T) {
	got := vethHostName("eth0", "0123456789abcdef")
	if got != "eth0+0123456789" {
		t.Fatalf("got %q, want the name the running daemons already use", got)
	}
}

func TestPodNICsToReleaseAlwaysCoversThePrimary(t *testing.T) {
	got := podNICsToRelease(nil, nil, "web", "uid-web", "eth0")
	if strings.Join(got, ",") != "eth0" {
		t.Fatalf("got %v, want the primary NIC alone", got)
	}
}

func TestPodNICsToReleaseCoversEveryEndpointOfThePod(t *testing.T) {
	endpoints := []juneauv1alpha1.NetworkEndpoint{
		{Spec: juneauv1alpha1.NetworkEndpointSpec{PodRef: &juneauv1alpha1.NetworkEndpointPodReference{Name: "web", UID: "uid-web", Interface: "eth1"}}},
		{Spec: juneauv1alpha1.NetworkEndpointSpec{PodRef: &juneauv1alpha1.NetworkEndpointPodReference{Name: "web", UID: "uid-web", Interface: "eth0"}}},
		{Spec: juneauv1alpha1.NetworkEndpointSpec{PodRef: &juneauv1alpha1.NetworkEndpointPodReference{Name: "other", UID: "uid-other", Interface: "eth1"}}},
	}
	got := podNICsToRelease(endpoints, nil, "web", "uid-web", "eth0")
	if strings.Join(got, ",") != "eth0,eth1" {
		t.Fatalf("got %v, want the NICs of this pod, primary first", got)
	}
}

func TestIsSandboxVethNameAcceptsTheNamesJuneauBuilds(t *testing.T) {
	const containerID = "0123456789abcdef0123456789abcdef"
	names := []string{
		vethHostName(juneauv1alpha1.PodPrimaryInterfaceName, containerID),
		vethHostName("eth1", containerID),
		vethHostName(strings.Repeat("e", juneauv1alpha1.PodInterfaceNameMaxLen), containerID),
		vethPeerName(0, containerID),
		vethPeerName(3, containerID),
	}
	for _, name := range names {
		if !isSandboxVethName(name, containerID) {
			t.Errorf("%q is a veth of this sandbox and must be taken down", name)
		}
	}
}

func TestIsSandboxVethNameSparesEverythingElse(t *testing.T) {
	const containerID = "0123456789abcdef0123456789abcdef"
	names := []string{
		"eth0",
		"ens3",
		"juneau_node_h",
		vethHostName("eth0", "fedcba98765432100123456789abcdef"),
		"eth0+0123456789abc",
		"eth0+01234",
		"+0123456789",
	}
	for _, name := range names {
		if isSandboxVethName(name, containerID) {
			t.Errorf("%q does not belong to this sandbox and must be left alone", name)
		}
	}
}

func TestVethPeerNameCannotCollideWithAPodInterface(t *testing.T) {
	const containerID = "0123456789abcdef0123456789abcdef"
	peer := vethPeerName(0, containerID)
	ifName, _, _ := strings.Cut(peer, vethNameSeparator)
	errs := juneauv1alpha1.ValidatePodNetworkAttachments(
		field.NewPath("test"),
		[]juneauv1alpha1.PodNetworkAttachment{{Interface: ifName, Subnet: "web"}},
	)
	if len(errs) == 0 {
		t.Fatalf("a pod may not ask for interface %q, or its NIC would clash with the temporary peer name", ifName)
	}
}

func TestCheckPodInterfacesComplete(t *testing.T) {
	wanted := []juneauv1alpha1.PodNetworkAttachment{
		{Interface: "eth0", Subnet: "web"},
		{Interface: "eth1", Subnet: "db"},
	}

	ready := []juneauv1alpha1.NetworkInterface{
		podInterface("eth0", "10.18.0.5/24", true),
		podInterface("eth1", "10.19.0.5/24", true),
	}
	if err := checkPodInterfacesComplete(orderPodInterfaces(ready, "eth0"), wanted); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	partial := []juneauv1alpha1.NetworkInterface{podInterface("eth0", "10.18.0.5/24", true)}
	err := checkPodInterfacesComplete(orderPodInterfaces(partial, "eth0"), wanted)
	if err == nil {
		t.Fatal("expected an error while a NIC the pod asked for has no NetworkInterface")
	}
	if !strings.Contains(err.Error(), "eth1") {
		t.Fatalf("error should name the missing NIC, got %v", err)
	}
}

func TestFilterPodInterfacesKeepsOnlyWhatThePodAsksFor(t *testing.T) {
	items := []juneauv1alpha1.NetworkInterface{
		podInterface("eth0", "10.18.0.5/24", true),
		podInterface("eth1", "10.19.0.5/24", true),
		podInterface("data0", "", false),
	}
	wanted := []juneauv1alpha1.PodNetworkAttachment{
		{Interface: "eth0", Subnet: "web"},
		{Interface: "eth1", Subnet: "db"},
	}
	got := ifnamesOf(filterPodInterfaces(orderPodInterfaces(items, "eth0"), wanted))
	if strings.Join(got, ",") != "eth0,eth1" {
		t.Fatalf("got %v, want the NICs the pod asks for", got)
	}
}

func TestPodNICsToReleaseCoversTheNICsThePodAsksFor(t *testing.T) {
	wanted := []juneauv1alpha1.PodNetworkAttachment{
		{Interface: "eth0", Subnet: "web"},
		{Interface: "eth1", Subnet: "db"},
	}
	got := podNICsToRelease(nil, wanted, "web", "uid-web", "eth0")
	if strings.Join(got, ",") != "eth0,eth1" {
		t.Fatalf("got %v, want every NIC of the pod even before the endpoints are cached", got)
	}
}

func TestPodNICsToReleaseMergesBothSources(t *testing.T) {
	endpoints := []juneauv1alpha1.NetworkEndpoint{
		{Spec: juneauv1alpha1.NetworkEndpointSpec{PodRef: &juneauv1alpha1.NetworkEndpointPodReference{Name: "web", UID: "uid-web", Interface: "data0"}}},
		{Spec: juneauv1alpha1.NetworkEndpointSpec{PodRef: &juneauv1alpha1.NetworkEndpointPodReference{Name: "web", UID: "uid-web", Interface: "eth1"}}},
	}
	wanted := []juneauv1alpha1.PodNetworkAttachment{
		{Interface: "eth0", Subnet: "web"},
		{Interface: "eth1", Subnet: "db"},
	}
	got := podNICsToRelease(endpoints, wanted, "web", "uid-web", "eth0")
	if strings.Join(got, ",") != "eth0,data0,eth1" {
		t.Fatalf("got %v, want the primary first and then every NIC either source knows", got)
	}
}
