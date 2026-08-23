package grpc

import (
	"context"
	"errors"
	"strings"
	"testing"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/daemon/pkg/cnipb"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

type fakeProbeRegistrar struct {
	unregistered []string
}

func (f *fakeProbeRegistrar) RegisterPod(ctx context.Context, namespace, name, uid, containerID, netnsPath, address string) error {
	return nil
}

func (f *fakeProbeRegistrar) UnregisterPod(uid, containerID string) error {
	f.unregistered = append(f.unregistered, uid+":"+containerID)
	return nil
}

func newTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = juneauv1alpha1.AddToScheme(scheme)
	return scheme
}

func indexNWEPByPodRefUID(obj client.Object) []string {
	nwep, ok := obj.(*juneauv1alpha1.NetworkEndpoint)
	if !ok || nwep.Spec.PodRef == nil {
		return nil
	}
	return []string{nwep.Spec.PodRef.UID}
}

func indexNWEPByPodRefName(obj client.Object) []string {
	nwep, ok := obj.(*juneauv1alpha1.NetworkEndpoint)
	if !ok || nwep.Spec.PodRef == nil {
		return nil
	}
	return []string{nwep.Spec.PodRef.Name}
}

func indexNWEPByPodRefInterface(obj client.Object) []string {
	nwep, ok := obj.(*juneauv1alpha1.NetworkEndpoint)
	if !ok || nwep.Spec.PodRef == nil {
		return nil
	}
	return []string{nwep.Spec.PodRef.Interface}
}

func newTestCNIServer(t *testing.T, objs ...client.Object) (*CNIServer, *fakeProbeRegistrar) {
	t.Helper()
	return newTestCNIServerWith(t, interceptor.Funcs{}, objs...)
}

func newTestCNIServerWith(t *testing.T, funcs interceptor.Funcs, objs ...client.Object) (*CNIServer, *fakeProbeRegistrar) {
	t.Helper()
	registrar := &fakeProbeRegistrar{}
	builder := fake.NewClientBuilder().
		WithScheme(newTestScheme()).
		WithIndex(&juneauv1alpha1.NetworkEndpoint{}, "spec.podRef.uid", indexNWEPByPodRefUID).
		WithIndex(&juneauv1alpha1.NetworkEndpoint{}, "spec.podRef.name", indexNWEPByPodRefName).
		WithIndex(&juneauv1alpha1.NetworkEndpoint{}, "spec.podRef.interface", indexNWEPByPodRefInterface)
	if len(objs) > 0 {
		builder = builder.WithObjects(objs...)
	}
	cached := builder.Build()
	return newCNIServer(cached, interceptor.NewClient(cached, funcs), registrar), registrar
}

func networkEndpointResource() schema.GroupResource {
	return schema.GroupResource{Group: juneauv1alpha1.GroupVersion.Group, Resource: "networkendpoints"}
}

func newTestNWEP(podName, ifname, podUID, containerID string, ifindex int) *juneauv1alpha1.NetworkEndpoint {
	return &juneauv1alpha1.NetworkEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      podName + "." + ifname,
		},
		Spec: juneauv1alpha1.NetworkEndpointSpec{
			Kind:     juneauv1alpha1.EndpointKindPod,
			NodeName: "node-a",
			Subnet:   "default",
			Address:  "10.0.0.1/24",
			PodRef: &juneauv1alpha1.NetworkEndpointPodReference{
				Name:      podName,
				Interface: ifname,
				UID:       podUID,
			},
			Attachment: &juneauv1alpha1.NetworkEndpointAttachment{
				Ifindex:        ifindex,
				HostMACAddress: "02:42:ac:10:00:11",
				ContainerID:    containerID,
			},
		},
	}
}

func TestUpsertNetworkEndpointCreatesThenRefreshesGeneration(t *testing.T) {
	server, _ := newTestCNIServer(t)
	ctx := context.Background()

	// ADD(S1): creates the endpoint.
	nwepS1 := newTestNWEP("pod-a", "eth0", "pod-uid-1", "container-s1-1", 1)
	created, err := server.upsertNetworkEndpoint(ctx, nwepS1, "pod-uid-1")
	if err != nil {
		t.Fatalf("ADD(S1): %v", err)
	}
	if !created {
		t.Fatal("ADD(S1) should report createdByUs=true")
	}

	// ADD(S2): same pod UID, new sandbox; attachment generation must be replaced.
	nwepS2 := newTestNWEP("pod-a", "eth0", "pod-uid-1", "container-s2-2", 2)
	nwepS2.Spec.MACAddress = "02:42:ac:10:00:22"
	createdByUs, err := server.upsertNetworkEndpoint(ctx, nwepS2, "pod-uid-1")
	if err != nil {
		t.Fatalf("ADD(S2): %v", err)
	}
	if createdByUs {
		t.Fatal("ADD(S2) should reuse the existing endpoint, not create")
	}

	var got juneauv1alpha1.NetworkEndpoint
	if err := server.apiClient.Get(ctx, client.ObjectKey{Namespace: "default", Name: "pod-a.eth0"}, &got); err != nil {
		t.Fatalf("get endpoint: %v", err)
	}
	if got.Spec.Attachment == nil || got.Spec.Attachment.ContainerID != "container-s2-2" {
		t.Fatalf("attachment generation not refreshed, got %+v", got.Spec.Attachment)
	}
	if got.Spec.Attachment.Ifindex != 2 {
		t.Fatalf("ifindex not refreshed, got %d", got.Spec.Attachment.Ifindex)
	}
	if got.Spec.MACAddress != "02:42:ac:10:00:22" {
		t.Fatalf("pod MAC not refreshed, got %s", got.Spec.MACAddress)
	}
	if got.Spec.PodRef.UID != "pod-uid-1" || got.Spec.Address != "10.0.0.1/24" {
		t.Fatalf("identity fields must be preserved, got podRef=%+v address=%s", got.Spec.PodRef, got.Spec.Address)
	}
}

func TestUpsertNetworkEndpointIdempotentRetry(t *testing.T) {
	server, _ := newTestCNIServer(t)
	ctx := context.Background()

	// ADD(S1) then a retried ADD(S1) with the same container ID: no-op refresh.
	nwepS1 := newTestNWEP("pod-a", "1net", "pod-uid-1", "container-s1-1", 1)
	if _, err := server.upsertNetworkEndpoint(ctx, nwepS1, "pod-uid-1"); err != nil {
		t.Fatalf("first ADD: %v", err)
	}
	retry := newTestNWEP("pod-a", "1net", "pod-uid-1", "container-s1-1", 1)
	createdByUs, err := server.upsertNetworkEndpoint(ctx, retry, "pod-uid-1")
	if err != nil {
		t.Fatalf("retried ADD: %v", err)
	}
	if createdByUs {
		t.Fatal("retried ADD must not report createdByUs=true")
	}

	var got juneauv1alpha1.NetworkEndpoint
	if err := server.apiClient.Get(ctx, client.ObjectKey{Namespace: "default", Name: "pod-a.1net"}, &got); err != nil {
		t.Fatalf("get endpoint: %v", err)
	}
	if got.Spec.Attachment.ContainerID != "container-s1-1" {
		t.Fatalf("attachment must remain the same generation, got %+v", got.Spec.Attachment)
	}
}

func TestUpsertNetworkEndpointRejectsUIDMismatch(t *testing.T) {
	server, _ := newTestCNIServer(t)
	ctx := context.Background()

	nwep := newTestNWEP("pod-a", "2", "pod-uid-1", "container-s1-1", 1)
	if _, err := server.upsertNetworkEndpoint(ctx, nwep, "pod-uid-1"); err != nil {
		t.Fatalf("ADD for uid-1: %v", err)
	}
	other := newTestNWEP("pod-a", "2", "pod-uid-2", "container-s1-1", 1)
	if _, err := server.upsertNetworkEndpoint(ctx, other, "pod-uid-2"); err == nil {
		t.Fatal("expected hard error for pod UID mismatch")
	}
}

func TestDelStaleGenerationIsNoop(t *testing.T) {
	nwep := newTestNWEP("pod-a", "eth0", "pod-uid-1", "container-s2-2", 2)
	server, registrar := newTestCNIServer(t, nwep)
	ctx := context.Background()

	// DEL(S1) after the endpoint moved to S2 must not delete the live endpoint
	// nor unregister its probes.
	req := &cnipb.CNIRequest{
		Args: map[string]string{
			PodNamespaceKey: "default",
			PodNameKey:      "pod-a",
			PodUIDKey:       "pod-uid-1",
		},
		Ifname:      "eth0",
		ContainerId: "container-s1-1",
	}
	if _, err := server.Del(ctx, req); err != nil {
		t.Fatalf("stale DEL: %v", err)
	}

	var got juneauv1alpha1.NetworkEndpoint
	if err := server.apiClient.Get(ctx, client.ObjectKey{Namespace: "default", Name: "pod-a.eth0"}, &got); err != nil {
		t.Fatalf("live endpoint must survive stale DEL, got err %v", err)
	}
	if len(registrar.unregistered) != 0 {
		t.Fatalf("stale DEL must not unregister probes, got %v", registrar.unregistered)
	}
}

func TestDelCurrentGenerationDeletesEndpointAndProbes(t *testing.T) {
	nwep := newTestNWEP("pod-a", "eth0", "pod-uid-1", "container-s1-1", 1)
	server, registrar := newTestCNIServer(t, nwep)
	ctx := context.Background()

	req := &cnipb.CNIRequest{
		Args: map[string]string{
			PodNamespaceKey: "default",
			PodNameKey:      "pod-a",
			PodUIDKey:       "pod-uid-1",
		},
		Ifname:      "eth0",
		ContainerId: "container-s1-1",
	}
	if _, err := server.Del(ctx, req); err != nil {
		t.Fatalf("DEL: %v", err)
	}

	var got juneauv1alpha1.NetworkEndpoint
	err := server.apiClient.Get(ctx, client.ObjectKey{Namespace: "default", Name: "pod-a.eth0"}, &got)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("endpoint should be deleted, got err %v", err)
	}
	if len(registrar.unregistered) != 1 || registrar.unregistered[0] != "pod-uid-1:container-s1-1" {
		t.Fatalf("unexpected probe unregistrations: %v", registrar.unregistered)
	}
}

func TestDelLegacyAttachmentWithoutGenerationStillDeletes(t *testing.T) {
	legacy := newTestNWEP("pod-a", "eth0", "pod-uid-1", "", 1)
	server, _ := newTestCNIServer(t, legacy)
	ctx := context.Background()

	// Endpoints created before this fix have an empty ContainerID; DEL must
	// still tear them down for upgrade compatibility.
	req := &cnipb.CNIRequest{
		Args: map[string]string{
			PodNamespaceKey: "default",
			PodNameKey:      "pod-a",
			PodUIDKey:       "pod-uid-1",
		},
		Ifname:      "eth0",
		ContainerId: "container-s1-1",
	}
	if _, err := server.Del(ctx, req); err != nil {
		t.Fatalf("DEL legacy: %v", err)
	}
	var got juneauv1alpha1.NetworkEndpoint
	err := server.apiClient.Get(ctx, client.ObjectKey{Namespace: "default", Name: "pod-a.eth0"}, &got)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("legacy endpoint should be deleted, got err %v", err)
	}
}

func TestDelWithNoEndpointIsIdempotent(t *testing.T) {
	server, registrar := newTestCNIServer(t)
	ctx := context.Background()

	req := &cnipb.CNIRequest{
		Args: map[string]string{
			PodNamespaceKey: "default",
			PodNameKey:      "pod-a",
			PodUIDKey:       "pod-uid-1",
		},
		Ifname:      "eth0",
		ContainerId: "container-s1-1",
	}
	if _, err := server.Del(ctx, req); err != nil {
		t.Fatalf("DEL when no endpoint exists: %v", err)
	}
	if len(registrar.unregistered) != 1 || registrar.unregistered[0] != "pod-uid-1:container-s1-1" {
		t.Fatalf("expected probe unregistration without endpoint, got %v", registrar.unregistered)
	}
}

func TestDelKeepsEndpointWhenDeleteRacesNewerGeneration(t *testing.T) {
	nwep := newTestNWEP("pod-a", "eth0", "pod-uid-1", "container-s1-1", 1)
	server, registrar := newTestCNIServerWith(t, interceptor.Funcs{
		Delete: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			// ADD(S2) lands between the read that decides the
			// generation and the delete that acts on it.
			var live juneauv1alpha1.NetworkEndpoint
			if err := cl.Get(ctx, client.ObjectKeyFromObject(obj), &live); err != nil {
				return err
			}
			live.Spec.Attachment.ContainerID = "container-s2-2"
			live.Spec.Attachment.Ifindex = 2
			if err := cl.Update(ctx, &live); err != nil {
				return err
			}
			return cl.Delete(ctx, obj, opts...)
		},
	}, nwep)
	ctx := context.Background()

	req := &cnipb.CNIRequest{
		Args: map[string]string{
			PodNamespaceKey: "default",
			PodNameKey:      "pod-a",
			PodUIDKey:       "pod-uid-1",
		},
		Ifname:      "eth0",
		ContainerId: "container-s1-1",
	}
	if _, err := server.Del(ctx, req); err != nil {
		t.Fatalf("racing DEL: %v", err)
	}

	var got juneauv1alpha1.NetworkEndpoint
	if err := server.apiClient.Get(ctx, client.ObjectKey{Namespace: "default", Name: "pod-a.eth0"}, &got); err != nil {
		t.Fatalf("endpoint claimed by the newer sandbox must survive, got err %v", err)
	}
	if got.Spec.Attachment.ContainerID != "container-s2-2" {
		t.Fatalf("newer attachment must be intact, got %+v", got.Spec.Attachment)
	}
	if len(registrar.unregistered) != 0 {
		t.Fatalf("racing DEL must not unregister probes, got %v", registrar.unregistered)
	}
}

func TestDelIgnoresEndpointOwnedByAnotherPod(t *testing.T) {
	nwep := newTestNWEP("pod-a", "eth0", "pod-uid-2", "container-s2-2", 2)
	server, _ := newTestCNIServer(t, nwep)
	ctx := context.Background()

	req := &cnipb.CNIRequest{
		Args: map[string]string{
			PodNamespaceKey: "default",
			PodNameKey:      "pod-a",
			PodUIDKey:       "pod-uid-1",
		},
		Ifname:      "eth0",
		ContainerId: "container-s1-1",
	}
	if _, err := server.Del(ctx, req); err != nil {
		t.Fatalf("DEL for a replaced pod: %v", err)
	}

	var got juneauv1alpha1.NetworkEndpoint
	if err := server.apiClient.Get(ctx, client.ObjectKey{Namespace: "default", Name: "pod-a.eth0"}, &got); err != nil {
		t.Fatalf("endpoint of the other pod must survive, got err %v", err)
	}
}

func TestUpsertNetworkEndpointRetriesUpdateConflict(t *testing.T) {
	updates := 0
	server, _ := newTestCNIServerWith(t, interceptor.Funcs{
		Update: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			updates++
			if updates == 1 {
				return apierrors.NewConflict(networkEndpointResource(), obj.GetName(), errors.New("stale resourceVersion"))
			}
			return cl.Update(ctx, obj, opts...)
		},
	})
	ctx := context.Background()

	nwepS1 := newTestNWEP("pod-a", "eth0", "pod-uid-1", "container-s1-1", 1)
	if _, err := server.upsertNetworkEndpoint(ctx, nwepS1, "pod-uid-1"); err != nil {
		t.Fatalf("ADD(S1): %v", err)
	}

	nwepS2 := newTestNWEP("pod-a", "eth0", "pod-uid-1", "container-s2-2", 2)
	createdByUs, err := server.upsertNetworkEndpoint(ctx, nwepS2, "pod-uid-1")
	if err != nil {
		t.Fatalf("ADD(S2) must survive one update conflict: %v", err)
	}
	if createdByUs {
		t.Fatal("ADD(S2) must not report createdByUs=true")
	}
	if updates < 2 {
		t.Fatalf("expected the update to be retried, got %d attempts", updates)
	}

	var got juneauv1alpha1.NetworkEndpoint
	if err := server.apiClient.Get(ctx, client.ObjectKey{Namespace: "default", Name: "pod-a.eth0"}, &got); err != nil {
		t.Fatalf("get endpoint: %v", err)
	}
	if got.Spec.Attachment.ContainerID != "container-s2-2" {
		t.Fatalf("attachment generation not refreshed, got %+v", got.Spec.Attachment)
	}
}

func TestUpsertNetworkEndpointRecreatesWhenRecordVanishes(t *testing.T) {
	creates, gets := 0, 0
	server, _ := newTestCNIServerWith(t, interceptor.Funcs{
		Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			creates++
			if creates == 1 {
				return apierrors.NewAlreadyExists(networkEndpointResource(), obj.GetName())
			}
			return cl.Create(ctx, obj, opts...)
		},
		Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			gets++
			if gets == 1 {
				return apierrors.NewNotFound(networkEndpointResource(), key.Name)
			}
			return cl.Get(ctx, key, obj, opts...)
		},
	})
	ctx := context.Background()

	nwep := newTestNWEP("pod-a", "eth0", "pod-uid-1", "container-s1-1", 1)
	createdByUs, err := server.upsertNetworkEndpoint(ctx, nwep, "pod-uid-1")
	if err != nil {
		t.Fatalf("ADD must retry the create when the record vanished: %v", err)
	}
	if !createdByUs {
		t.Fatal("the retried create inserted the endpoint, so createdByUs must be true")
	}

	var got juneauv1alpha1.NetworkEndpoint
	if err := server.apiClient.Get(ctx, client.ObjectKey{Namespace: "default", Name: "pod-a.eth0"}, &got); err != nil {
		t.Fatalf("get endpoint: %v", err)
	}
	if got.Spec.Attachment.ContainerID != "container-s1-1" {
		t.Fatalf("unexpected attachment, got %+v", got.Spec.Attachment)
	}
}

func captureLogs(t *testing.T) *observer.ObservedLogs {
	t.Helper()
	core, logs := observer.New(zapcore.DebugLevel)
	restore := zap.ReplaceGlobals(zap.New(core))
	t.Cleanup(restore)
	return logs
}

func hasLogEntry(logs *observer.ObservedLogs, level zapcore.Level, fragments ...string) bool {
	for _, entry := range logs.All() {
		if entry.Level != level {
			continue
		}
		matched := true
		for _, fragment := range fragments {
			if !strings.Contains(entry.Message, fragment) {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func TestDelStaleGenerationLogsAtInfo(t *testing.T) {
	nwep := newTestNWEP("pod-a", "eth0", "pod-uid-1", "container-s2-2", 2)
	server, _ := newTestCNIServer(t, nwep)
	logs := captureLogs(t)

	req := &cnipb.CNIRequest{
		Args: map[string]string{
			PodNamespaceKey: "default",
			PodNameKey:      "pod-a",
			PodUIDKey:       "pod-uid-1",
		},
		Ifname:      "eth0",
		ContainerId: "container-s1-1",
	}
	if _, err := server.Del(context.Background(), req); err != nil {
		t.Fatalf("stale DEL: %v", err)
	}

	if !hasLogEntry(logs, zapcore.InfoLevel, "default/pod-a", "eth0", "container-s1-1", "container-s2-2") {
		t.Fatalf("stale DEL must be reported at info level with both generations, got %v", logs.All())
	}
}

func TestDelLogsRequestWithContainerID(t *testing.T) {
	server, _ := newTestCNIServer(t)
	logs := captureLogs(t)

	req := &cnipb.CNIRequest{
		Args: map[string]string{
			PodNamespaceKey: "default",
			PodNameKey:      "pod-a",
			PodUIDKey:       "pod-uid-1",
		},
		Ifname:      "eth0",
		ContainerId: "container-s1-1",
	}
	if _, err := server.Del(context.Background(), req); err != nil {
		t.Fatalf("DEL: %v", err)
	}

	if !hasLogEntry(logs, zapcore.InfoLevel, "CNI DEL request", "container-s1-1") {
		t.Fatalf("DEL request log must carry the container ID, got %v", logs.All())
	}
}

func TestDelAcceptsShortContainerID(t *testing.T) {
	nwep := newTestNWEP("pod-a", "eth0", "pod-uid-1", "abc", 1)
	server, registrar := newTestCNIServer(t, nwep)

	req := &cnipb.CNIRequest{
		Args: map[string]string{
			PodNamespaceKey: "default",
			PodNameKey:      "pod-a",
			PodUIDKey:       "pod-uid-1",
		},
		Ifname:      "eth0",
		ContainerId: "abc",
	}
	if _, err := server.Del(context.Background(), req); err != nil {
		t.Fatalf("DEL with a short container ID: %v", err)
	}
	if len(registrar.unregistered) != 1 || registrar.unregistered[0] != "pod-uid-1:abc" {
		t.Fatalf("unexpected probe unregistrations: %v", registrar.unregistered)
	}
}
