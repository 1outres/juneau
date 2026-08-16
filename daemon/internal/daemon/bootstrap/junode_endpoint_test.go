package bootstrap

import (
	"context"
	"errors"
	"net"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

const (
	testNamespace = "kube-system"
	testNodeName  = "worker-1"
)

func testEndpoint(attachment *juneauv1alpha1.NetworkEndpointAttachment) *juneauv1alpha1.NetworkEndpoint {
	return &juneauv1alpha1.NetworkEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      juneauv1alpha1.JuneauNodeEndpointName(testNodeName),
		},
		Spec: juneauv1alpha1.NetworkEndpointSpec{
			Kind:       juneauv1alpha1.EndpointKindNode,
			NodeName:   testNodeName,
			Subnet:     "default",
			Address:    "10.16.0.9/16",
			MACAddress: "02:00:0a:10:00:09",
			Attachment: attachment,
		},
	}
}

func identityEndpoint(address, mac string) *juneauv1alpha1.NetworkEndpoint {
	endpoint := testEndpoint(nil)
	endpoint.Spec.Address = address
	endpoint.Spec.MACAddress = mac
	return endpoint
}

func otherNodeEndpoint() *juneauv1alpha1.NetworkEndpoint {
	return &juneauv1alpha1.NetworkEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      juneauv1alpha1.JuneauNodeEndpointName("worker-2"),
		},
		Spec: juneauv1alpha1.NetworkEndpointSpec{
			Kind:       juneauv1alpha1.EndpointKindNode,
			NodeName:   "worker-2",
			Subnet:     "default",
			Address:    "10.16.0.10/16",
			MACAddress: "02:00:0a:10:00:0a",
		},
	}
}

func testIfaceInfo(ifindex int) *JuneauNodeIfaceInfo {
	mac, err := net.ParseMAC("02:00:0a:10:00:09")
	if err != nil {
		panic(err)
	}
	return &JuneauNodeIfaceInfo{
		HostIfaceInfo: HostIfaceInfo{MAC: mac, Ifindex: ifindex},
		HostSideMAC:   mac,
		AssignedIP:    net.ParseIP("10.16.0.9"),
	}
}

func newPatchFixture(objects ...client.Object) (client.Client, *int) {
	return newPatchFixtureWithConflicts(0, objects...)
}

// newPatchFixtureWithConflicts answers the first `conflicts` updates the
// way the API server answers a write built on a resourceVersion the
// object has already moved past.
func newPatchFixtureWithConflicts(conflicts int, objects ...client.Object) (client.Client, *int) {
	scheme := runtime.NewScheme()
	utilruntime.Must(juneauv1alpha1.AddToScheme(scheme))

	updates := 0
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objects...).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				updates++
				if updates <= conflicts {
					return apierrors.NewConflict(
						juneauv1alpha1.GroupVersion.WithResource("networkendpoints").GroupResource(),
						obj.GetName(),
						errors.New("the object has been modified"),
					)
				}
				return inner.Update(ctx, obj, opts...)
			},
		}).
		Build()
	return cl, &updates
}

func TestFindJuneauNodeEndpointIgnoresNamespace(t *testing.T) {
	// The controller writes the endpoint in its own namespace, which is
	// not the daemon's, so the daemon must not assume either one.
	endpoint := testEndpoint(nil)
	endpoint.Namespace = "juneau-system"
	cl, _ := newPatchFixture(endpoint, otherNodeEndpoint())

	got, err := FindJuneauNodeEndpoint(context.Background(), cl, testNodeName)
	if err != nil {
		t.Fatalf("FindJuneauNodeEndpoint: %v", err)
	}
	if got.Namespace != "juneau-system" || got.Spec.NodeName != testNodeName {
		t.Errorf("found %s/%s for node %q", got.Namespace, got.Name, got.Spec.NodeName)
	}
}

func TestFindJuneauNodeEndpointRejectsDuplicates(t *testing.T) {
	legacy := testEndpoint(nil)
	legacy.Namespace = "juneau-system"
	cl, _ := newPatchFixture(testEndpoint(nil), legacy)

	if _, err := FindJuneauNodeEndpoint(context.Background(), cl, testNodeName); err == nil {
		t.Fatal("FindJuneauNodeEndpoint accepted two endpoints for one node, want an error")
	}
}

// mustFindTestEndpoint mirrors Converge: the endpoint is read once and
// handed to the patch step. The missing-endpoint case now lives with
// Converge, which owns the lookup.
func mustFindTestEndpoint(t *testing.T, cl client.Client) *juneauv1alpha1.NetworkEndpoint {
	t.Helper()
	endpoint, err := FindJuneauNodeEndpoint(context.Background(), cl, testNodeName)
	if err != nil {
		t.Fatalf("FindJuneauNodeEndpoint: %v", err)
	}
	return endpoint
}

func TestPatchJuneauNodeAttachmentWritesNewIfindex(t *testing.T) {
	cl, updates := newPatchFixture(testEndpoint(&juneauv1alpha1.NetworkEndpointAttachment{
		Ifindex:        7,
		HostMACAddress: "02:00:0a:10:00:09",
	}))

	if err := patchJuneauNodeAttachment(context.Background(), cl, mustFindTestEndpoint(t, cl), testIfaceInfo(12)); err != nil {
		t.Fatalf("patchJuneauNodeAttachment: %v", err)
	}
	if *updates != 1 {
		t.Errorf("updates = %d, want 1", *updates)
	}

	var got juneauv1alpha1.NetworkEndpoint
	key := client.ObjectKey{Namespace: testNamespace, Name: juneauv1alpha1.JuneauNodeEndpointName(testNodeName)}
	if err := cl.Get(context.Background(), key, &got); err != nil {
		t.Fatalf("get endpoint: %v", err)
	}
	if got.Spec.Attachment == nil || got.Spec.Attachment.Ifindex != 12 {
		t.Errorf("attachment = %+v, want ifindex 12", got.Spec.Attachment)
	}
	if got.Spec.Address != "10.16.0.9/16" || got.Spec.MACAddress != "02:00:0a:10:00:09" {
		t.Errorf("identity changed: address=%q macAddress=%q", got.Spec.Address, got.Spec.MACAddress)
	}
}

func TestPatchJuneauNodeAttachmentWritesNewHostMAC(t *testing.T) {
	// The upgrade case: the controller replaced the endpoint with a
	// derived MAC while the veth still advertised the old random one.
	cl, updates := newPatchFixture(testEndpoint(&juneauv1alpha1.NetworkEndpointAttachment{
		Ifindex:        12,
		HostMACAddress: "06:d5:49:80:ba:c1",
	}))

	if err := patchJuneauNodeAttachment(context.Background(), cl, mustFindTestEndpoint(t, cl), testIfaceInfo(12)); err != nil {
		t.Fatalf("patchJuneauNodeAttachment: %v", err)
	}
	if *updates != 1 {
		t.Errorf("updates = %d, want 1", *updates)
	}

	var got juneauv1alpha1.NetworkEndpoint
	key := client.ObjectKey{Namespace: testNamespace, Name: juneauv1alpha1.JuneauNodeEndpointName(testNodeName)}
	if err := cl.Get(context.Background(), key, &got); err != nil {
		t.Fatalf("get endpoint: %v", err)
	}
	if got.Spec.Attachment == nil || got.Spec.Attachment.HostMACAddress != "02:00:0a:10:00:09" {
		t.Errorf("attachment = %+v, want hostMACAddress 02:00:0a:10:00:09", got.Spec.Attachment)
	}
}

func TestPatchJuneauNodeAttachmentRetriesOnConflict(t *testing.T) {
	// What happens on a real identity change: the converger reads the
	// endpoint from the informer cache, the controller writes to it, and
	// the daemon's write arrives against a version the server has left
	// behind. The retry has to fix it, not the caller.
	cl, updates := newPatchFixtureWithConflicts(1, testEndpoint(nil))

	if err := patchJuneauNodeAttachment(context.Background(), cl, mustFindTestEndpoint(t, cl), testIfaceInfo(12)); err != nil {
		t.Fatalf("patchJuneauNodeAttachment: %v", err)
	}
	if *updates != 2 {
		t.Errorf("updates = %d, want 2 (one conflict, one success)", *updates)
	}

	var got juneauv1alpha1.NetworkEndpoint
	key := client.ObjectKey{Namespace: testNamespace, Name: juneauv1alpha1.JuneauNodeEndpointName(testNodeName)}
	if err := cl.Get(context.Background(), key, &got); err != nil {
		t.Fatalf("get endpoint: %v", err)
	}
	if got.Spec.Attachment == nil || got.Spec.Attachment.Ifindex != 12 {
		t.Errorf("attachment = %+v, want ifindex 12", got.Spec.Attachment)
	}
}

func TestPatchJuneauNodeAttachmentGivesUpOnEndlessConflicts(t *testing.T) {
	// A conflict that never clears is a real problem, so it still
	// reaches the caller and the work queue retries the whole pass.
	cl, _ := newPatchFixtureWithConflicts(100, testEndpoint(nil))

	err := patchJuneauNodeAttachment(context.Background(), cl, mustFindTestEndpoint(t, cl), testIfaceInfo(12))
	if !apierrors.IsConflict(err) {
		t.Fatalf("err = %v, want a conflict", err)
	}
}

func TestPatchJuneauNodeAttachmentSkipsWriteWhenEqual(t *testing.T) {
	cl, updates := newPatchFixture(testEndpoint(&juneauv1alpha1.NetworkEndpointAttachment{
		Ifindex:        12,
		HostMACAddress: "02:00:0a:10:00:09",
	}))

	if err := patchJuneauNodeAttachment(context.Background(), cl, mustFindTestEndpoint(t, cl), testIfaceInfo(12)); err != nil {
		t.Fatalf("patchJuneauNodeAttachment: %v", err)
	}
	if *updates != 0 {
		t.Errorf("updates = %d, want 0", *updates)
	}
}

func TestPatchJuneauNodeAttachmentFillsEmptyAttachment(t *testing.T) {
	cl, updates := newPatchFixture(testEndpoint(nil))

	if err := patchJuneauNodeAttachment(context.Background(), cl, mustFindTestEndpoint(t, cl), testIfaceInfo(12)); err != nil {
		t.Fatalf("patchJuneauNodeAttachment: %v", err)
	}
	if *updates != 1 {
		t.Errorf("updates = %d, want 1", *updates)
	}
}

func TestParseJuneauNodeIdentity(t *testing.T) {
	got, err := parseJuneauNodeIdentity(identityEndpoint("10.16.0.9/16", "02:00:0a:10:00:09"))
	if err != nil {
		t.Fatalf("parseJuneauNodeIdentity: %v", err)
	}

	wantIP := net.ParseIP("10.16.0.9")
	if !got.Address.IP.Equal(wantIP) {
		t.Errorf("IP = %v, want %v", got.Address.IP, wantIP)
	}
	if prefixLen, _ := got.Address.Mask.Size(); prefixLen != 16 {
		t.Errorf("prefix length = %d, want 16", prefixLen)
	}
	if got.MAC.String() != "02:00:0a:10:00:09" {
		t.Errorf("MAC = %s, want 02:00:0a:10:00:09", got.MAC)
	}
}

func TestParseJuneauNodeIdentityRejectsBadInput(t *testing.T) {
	cases := []struct {
		name    string
		address string
		mac     string
	}{
		{name: "no address", address: "", mac: "02:00:0a:10:00:09"},
		{name: "address without prefix", address: "10.16.0.9", mac: "02:00:0a:10:00:09"},
		{name: "unparseable address", address: "not-an-address", mac: "02:00:0a:10:00:09"},
		{name: "no MAC", address: "10.16.0.9/16", mac: ""},
		{name: "unparseable MAC", address: "10.16.0.9/16", mac: "zz:00:0a:10:00:09"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseJuneauNodeIdentity(identityEndpoint(tc.address, tc.mac)); err == nil {
				t.Fatal("parseJuneauNodeIdentity succeeded, want an error")
			}
		})
	}
}
