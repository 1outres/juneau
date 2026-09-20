package dns

import (
	"context"
	"errors"
	"testing"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const testVPCIDIndexField = "status.vpcID"

func newVPCResolverClient(t *testing.T, withIndex bool, vpcs ...*juneauv1alpha1.Vpc) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := juneauv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add Juneau scheme: %v", err)
	}
	objects := make([]client.Object, len(vpcs))
	for i := range vpcs {
		objects[i] = vpcs[i]
	}
	builder := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...)
	if withIndex {
		builder = builder.WithIndex(&juneauv1alpha1.Vpc{}, testVPCIDIndexField, vpcIDIndexValues)
	}
	return builder.Build()
}

func testVPC(name string, id uint32, consume bool) *juneauv1alpha1.Vpc {
	return &juneauv1alpha1.Vpc{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: juneauv1alpha1.VpcSpec{
			Service: &juneauv1alpha1.VpcServiceSpec{Consume: consume},
		},
		Status: juneauv1alpha1.VpcStatus{VpcID: id},
	}
}

type exactVPCListGuardClient struct {
	client.Client
	expectedKey string
}

func (c exactVPCListGuardClient) List(ctx context.Context, list client.ObjectList, options ...client.ListOption) error {
	if _, ok := list.(*juneauv1alpha1.VpcList); !ok {
		return c.Client.List(ctx, list, options...)
	}
	listOptions := &client.ListOptions{}
	for _, option := range options {
		option.ApplyToList(listOptions)
	}
	if listOptions.FieldSelector == nil {
		return errors.New("unfiltered VpcList")
	}
	value, found := listOptions.FieldSelector.RequiresExactMatch(testVPCIDIndexField)
	if !found || value != c.expectedKey {
		return errors.New("VpcList does not use the exact Vpc ID index")
	}
	return c.Client.List(ctx, list, options...)
}

func TestCachedVPCResolverUsesExactIndexedLookup(t *testing.T) {
	base := newVPCResolverClient(t, true, testVPC("tenant-a", 42, true), testVPC("tenant-b", 7, false))
	resolver := NewCachedVPCResolver(exactVPCListGuardClient{Client: base, expectedKey: "42"})

	name, serviceEnabled, consume, ok := resolver.LookupByID(context.Background(), 42)
	if !ok {
		t.Fatal("LookupByID did not find indexed Vpc")
	}
	if name != "tenant-a" || !serviceEnabled || !consume {
		t.Fatalf("LookupByID = (%q, %t, %t), want tenant-a with Service enabled and Consume", name, serviceEnabled, consume)
	}
}

func TestCachedVPCResolverTreatsMissingIndexAsUnresolved(t *testing.T) {
	resolver := NewCachedVPCResolver(newVPCResolverClient(t, false, testVPC("tenant-a", 42, true)))

	name, serviceEnabled, consume, ok := resolver.LookupByID(context.Background(), 42)
	if ok || name != "" || serviceEnabled || consume {
		t.Fatalf("LookupByID = (%q, %t, %t, %t), want unresolved", name, serviceEnabled, consume, ok)
	}
}

func TestCachedVPCResolverTreatsDuplicateIDsAsUnresolved(t *testing.T) {
	resolver := NewCachedVPCResolver(newVPCResolverClient(t, true,
		testVPC("tenant-a", 42, true),
		testVPC("tenant-b", 42, false),
	))

	name, serviceEnabled, consume, ok := resolver.LookupByID(context.Background(), 42)
	if ok || name != "" || serviceEnabled || consume {
		t.Fatalf("LookupByID = (%q, %t, %t, %t), want unresolved duplicate", name, serviceEnabled, consume, ok)
	}
}

type rejectingVPCListClient struct {
	client.Client
	calls int
}

func (c *rejectingVPCListClient) List(context.Context, client.ObjectList, ...client.ListOption) error {
	c.calls++
	return errors.New("unexpected List")
}

func TestCachedVPCResolverRejectsZeroWithoutListing(t *testing.T) {
	guard := &rejectingVPCListClient{Client: newVPCResolverClient(t, true)}
	resolver := NewCachedVPCResolver(guard)

	name, serviceEnabled, consume, ok := resolver.LookupByID(context.Background(), 0)
	if ok || name != "" || serviceEnabled || consume {
		t.Fatalf("LookupByID = (%q, %t, %t, %t), want unresolved zero", name, serviceEnabled, consume, ok)
	}
	if guard.calls != 0 {
		t.Fatalf("List calls = %d, want 0", guard.calls)
	}
}

func TestCachedVPCResolverTreatsMissingIDAndListErrorsAsUnresolved(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		resolver := NewCachedVPCResolver(newVPCResolverClient(t, true, testVPC("tenant-a", 42, true)))
		_, _, _, ok := resolver.LookupByID(context.Background(), 99)
		if ok {
			t.Fatal("LookupByID found a missing ID")
		}
	})

	t.Run("list error", func(t *testing.T) {
		resolver := NewCachedVPCResolver(&rejectingVPCListClient{Client: newVPCResolverClient(t, true)})
		_, _, _, ok := resolver.LookupByID(context.Background(), 42)
		if ok {
			t.Fatal("LookupByID succeeded after a List error")
		}
	})
}
