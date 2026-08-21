package reconciler

import (
	"context"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
)

type fakeBpfMap struct {
	entries map[any]any
	deletes int
}

func newFakeBpfMap() *fakeBpfMap {
	return &fakeBpfMap{entries: make(map[any]any)}
}

func (m *fakeBpfMap) Update(key, value any, _ ebpf.MapUpdateFlags) error {
	m.entries[indirectValue(key)] = indirectValue(value)
	return nil
}

func (m *fakeBpfMap) Delete(key any) error {
	key = indirectValue(key)
	if _, ok := m.entries[key]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(m.entries, key)
	m.deletes++
	return nil
}

func indirectValue(value any) any {
	v := reflect.ValueOf(value)
	if v.Kind() == reflect.Pointer {
		return v.Elem().Interface()
	}
	return value
}

func newNatTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	utilruntime.Must(juneauv1alpha1.AddToScheme(scheme))
	return scheme
}

func newNatFixture(t *testing.T, attachmentNode string, includeAttachment bool) (*Nat, *fakeBpfMap, *fakeBpfMap, *juneauv1alpha1.ElasticIPAttachment) {
	t.Helper()

	attachment := &juneauv1alpha1.ElasticIPAttachment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "eip-a"},
		Spec: juneauv1alpha1.ElasticIPAttachmentSpec{
			TargetRef: juneauv1alpha1.ElasticIPAttachmentTargetRef{NetworkInterfaceName: "nic-a"},
		},
		Status: juneauv1alpha1.ElasticIPAttachmentStatus{
			Phase:     juneauv1alpha1.ElasticIPAttachmentPhaseAttached,
			ElasticIP: "192.0.2.10",
			PodIP:     "10.0.0.10",
			NodeName:  attachmentNode,
		},
	}
	nic := &juneauv1alpha1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "nic-a"},
		Spec: juneauv1alpha1.NetworkInterfaceSpec{
			Subnet: "subnet-a",
		},
	}
	subnet := &juneauv1alpha1.Subnet{
		ObjectMeta: metav1.ObjectMeta{Name: "subnet-a"},
		Status:     juneauv1alpha1.SubnetStatus{VNI: 42},
	}

	objects := []runtime.Object{nic, subnet}
	if includeAttachment {
		objects = append(objects, attachment)
	}
	cl := fake.NewClientBuilder().WithScheme(newNatTestScheme(t)).WithRuntimeObjects(objects...).Build()
	dnatMap := newFakeBpfMap()
	snatMap := newFakeBpfMap()
	r := &Nat{
		client:    cl,
		dnatMap:   dnatMap,
		snatMap:   snatMap,
		nodeName:  "node-a",
		snapshots: make(map[string]natSnapshot),
	}
	return r, dnatMap, snatMap, attachment
}

func TestNatReconcileProgramsDNATOnEveryNode(t *testing.T) {
	tests := []struct {
		name           string
		attachmentNode string
		wantSNAT       int
	}{
		{name: "target Pod is local", attachmentNode: "node-a", wantSNAT: 1},
		{name: "target Pod is remote", attachmentNode: "node-b", wantSNAT: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, dnatMap, snatMap, _ := newNatFixture(t, tt.attachmentNode, true)
			if err := r.Reconcile(context.Background(), "default/eip-a"); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}

			if got := len(dnatMap.entries); got != 1 {
				t.Fatalf("DNAT entries = %d, want 1", got)
			}
			if got := len(snatMap.entries); got != tt.wantSNAT {
				t.Fatalf("SNAT entries = %d, want %d", got, tt.wantSNAT)
			}
			for _, value := range dnatMap.entries {
				inside := value.(bpf.PodEgressNatInside)
				if inside.SubnetId != 42 {
					t.Errorf("DNAT subnet ID = %d, want 42", inside.SubnetId)
				}
			}
		})
	}
}

func TestNatOwnerMoveRemovesLocalSNATAndKeepsDNAT(t *testing.T) {
	r, dnatMap, snatMap, attachment := newNatFixture(t, "node-a", false)
	if err := r.upsert(context.Background(), "default/eip-a", attachment); err != nil {
		t.Fatalf("initial upsert: %v", err)
	}

	attachment.Status.NodeName = "node-b"
	if err := r.upsert(context.Background(), "default/eip-a", attachment); err != nil {
		t.Fatalf("upsert after owner move: %v", err)
	}

	if got := len(dnatMap.entries); got != 1 {
		t.Errorf("DNAT entries after owner move = %d, want 1", got)
	}
	if dnatMap.deletes != 0 {
		t.Errorf("DNAT deletes during owner move = %d, want 0", dnatMap.deletes)
	}
	if got := len(snatMap.entries); got != 0 {
		t.Errorf("SNAT entries after owner move = %d, want 0", got)
	}
	if r.snapshots["default/eip-a"].programSNAT {
		t.Error("snapshot still marks SNAT as locally owned")
	}
}

func TestNatDeletionRemovesInstalledEntries(t *testing.T) {
	r, dnatMap, snatMap, attachment := newNatFixture(t, "node-a", false)
	if err := r.upsert(context.Background(), "default/eip-a", attachment); err != nil {
		t.Fatalf("initial upsert: %v", err)
	}

	if err := r.Reconcile(context.Background(), "default/eip-a"); err != nil {
		t.Fatalf("Reconcile deleted attachment: %v", err)
	}
	if got := len(dnatMap.entries); got != 0 {
		t.Errorf("DNAT entries after deletion = %d, want 0", got)
	}
	if got := len(snatMap.entries); got != 0 {
		t.Errorf("SNAT entries after deletion = %d, want 0", got)
	}
}
