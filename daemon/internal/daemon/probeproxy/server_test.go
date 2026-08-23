package probeproxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	probeconfig "github.com/1outres/juneau/controller/pkg/probe"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestExecuteHTTPInTargetNamespace(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ready" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		if r.URL.Query().Get("full") != "true" {
			t.Fatalf("unexpected query %q", r.URL.RawQuery)
		}
		if r.Host != "health.example" {
			t.Fatalf("unexpected Host %q", r.Host)
		}
		if got := r.Header.Get("Accept-Encoding"); got != "" {
			t.Fatalf("probe must not negotiate response compression, got %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	host, port := splitServerAddress(t, server.URL)
	dial := (&net.Dialer{}).DialContext
	err := executeWithDial(context.Background(), target{
		host: host,
		config: probeconfig.Config{
			Type: "http", Port: port, Path: "/ready?full=true", Timeout: 1,
			Headers: []probeconfig.Header{{Name: "Host", Value: "health.example"}},
		},
	}, dial)
	if err != nil {
		t.Fatalf("execute HTTP probe: %v", err)
	}
}

func TestExecuteHTTPSendsProbeUserAgent(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		headers []probeconfig.Header
		want    string
	}{
		{name: "default", want: "kube-probe/juneau"},
		{
			name:    "custom",
			headers: []probeconfig.Header{{Name: "User-Agent", Value: "custom-probe/1"}},
			want:    "custom-probe/1",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Values("User-Agent"); len(got) != 1 || got[0] != testCase.want {
					t.Errorf("User-Agent = %v, want [%q]", got, testCase.want)
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()
			host, port := splitServerAddress(t, server.URL)
			err := executeWithDial(context.Background(), target{
				host:   host,
				config: probeconfig.Config{Type: "http", Port: port, Timeout: 1, Headers: testCase.headers},
			}, (&net.Dialer{}).DialContext)
			if err != nil {
				t.Fatalf("execute HTTP probe: %v", err)
			}
		})
	}
}

func TestPublishRejectsCollisionWithoutDroppingExistingTargets(t *testing.T) {
	proxy := NewServer(nil, "", t.TempDir())
	first := probeconfig.Configs{"shared": {Type: "tcp", Port: 80}}
	if err := proxy.publish("first", "", "/first", "10.0.0.1", first); err != nil {
		t.Fatal(err)
	}
	if err := proxy.publish("second", "", "/second", "10.0.0.2", probeconfig.Configs{
		"other":  {Type: "tcp", Port: 80},
		"shared": {Type: "tcp", Port: 81},
	}); err == nil {
		t.Fatal("expected token collision")
	}
	if got := proxy.targets["shared"].podUID; got != "first" {
		t.Fatalf("existing target belongs to %q after collision", got)
	}
	if _, exists := proxy.targets["other"]; exists {
		t.Fatal("partially published a colliding Pod")
	}
}

func TestUnregisterPodIgnoresStaleContainerGeneration(t *testing.T) {
	proxy := NewServer(nil, "", t.TempDir())
	configs := probeconfig.Configs{"ready": {Type: "tcp", Port: 80}}
	if err := proxy.publish("pod-uid", "container-s2", "/pinned/netns", "10.0.0.1", configs); err != nil {
		t.Fatal(err)
	}

	if err := proxy.UnregisterPod("pod-uid", "container-s1"); err != nil {
		t.Fatalf("stale unregister: %v", err)
	}
	if got := proxy.containerIDs["pod-uid"]; got != "container-s2" {
		t.Fatalf("live generation changed to %q", got)
	}
	if _, exists := proxy.targets["ready"]; !exists {
		t.Fatal("stale unregister removed the live probe target")
	}

	// State is removed before the best-effort namespace unpin, so verify the
	// matching generation is released even on an unprivileged test host.
	_ = proxy.UnregisterPod("pod-uid", "container-s2")
	if _, exists := proxy.containerIDs["pod-uid"]; exists {
		t.Fatal("matching unregister retained the container generation")
	}
	if _, exists := proxy.targets["ready"]; exists {
		t.Fatal("matching unregister retained the probe target")
	}
}

func TestExecuteTCPReportsBackendFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().(*net.TCPAddr)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	dial := (&net.Dialer{}).DialContext
	err = executeWithDial(context.Background(), target{
		host:   address.IP.String(),
		config: probeconfig.Config{Type: "tcp", Port: int32(address.Port), Timeout: 1},
	}, dial)
	if err == nil {
		t.Fatal("expected a closed TCP target to fail")
	}
}

func TestServeHTTPRejectsUnknownToken(t *testing.T) {
	proxy := NewServer(nil, "", t.TempDir())
	request := httptest.NewRequest(http.MethodGet, probeconfig.EndpointPathPrefix+"unknown", nil)
	response := httptest.NewRecorder()
	proxy.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
}

func splitServerAddress(t *testing.T, rawURL string) (string, int32) {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	host, rawPort, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatal(err)
	}
	return host, int32(port)
}

func newRecoveryClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := juneauv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(&juneauv1alpha1.NetworkEndpoint{}, "spec.podRef.uid", func(obj client.Object) []string {
			endpoint, ok := obj.(*juneauv1alpha1.NetworkEndpoint)
			if !ok || endpoint.Spec.PodRef == nil {
				return nil
			}
			return []string{endpoint.Spec.PodRef.UID}
		}).
		WithObjects(objs...).
		Build()
}

func newProbePod(t *testing.T, uid string, configs probeconfig.Configs) *corev1.Pod {
	t.Helper()
	encoded, err := probeconfig.Encode(configs)
	if err != nil {
		t.Fatal(err)
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "pod-a",
			UID:       types.UID(uid),
			Annotations: map[string]string{
				probeconfig.AnnotationRewriteVersion: probeconfig.RewriteVersion,
				probeconfig.AnnotationConfigs:        encoded,
			},
		},
	}
}

func newProbeEndpoint(name, podUID, ifname, address string, attachment *juneauv1alpha1.NetworkEndpointAttachment) *juneauv1alpha1.NetworkEndpoint {
	return &juneauv1alpha1.NetworkEndpoint{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name},
		Spec: juneauv1alpha1.NetworkEndpointSpec{
			Kind:     juneauv1alpha1.EndpointKindPod,
			NodeName: "node-a",
			Address:  address,
			PodRef: &juneauv1alpha1.NetworkEndpointPodReference{
				Name:      "pod-a",
				Interface: ifname,
				UID:       podUID,
			},
			Attachment: attachment,
		},
	}
}

func pinNetNSDir(t *testing.T, uid string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, uid), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRecoverReadsAddressAndContainerIDFromOneEndpoint(t *testing.T) {
	configs := probeconfig.Configs{"ready": {Type: "tcp", Port: 80, Timeout: 1}}
	pod := newProbePod(t, "pod-uid-1", configs)
	live := newProbeEndpoint("pod-a.eth0", "pod-uid-1", "eth0", "10.0.0.1/24", nil)
	duplicate := newProbeEndpoint("pod-a.eth0.old", "pod-uid-1", "eth0", "10.0.0.2/24",
		&juneauv1alpha1.NetworkEndpointAttachment{Ifindex: 2, ContainerID: "container-s2"})

	proxy := NewServer(newRecoveryClient(t, pod, live, duplicate), "", pinNetNSDir(t, "pod-uid-1"))
	if err := proxy.Recover(context.Background(), "node-a"); err != nil {
		t.Fatalf("recover: %v", err)
	}

	host := proxy.targets["ready"].host
	containerID := proxy.containerIDs["pod-uid-1"]
	switch {
	case host == "10.0.0.1" && containerID == "":
	case host == "10.0.0.2" && containerID == "container-s2":
	default:
		t.Fatalf("address %q and container ID %q come from different endpoints", host, containerID)
	}
}

func TestRecoverIgnoresSecondaryInterfaces(t *testing.T) {
	configs := probeconfig.Configs{"ready": {Type: "tcp", Port: 80, Timeout: 1}}
	pod := newProbePod(t, "pod-uid-1", configs)
	primary := newProbeEndpoint("pod-a.eth0", "pod-uid-1", "eth0", "10.0.0.1/24",
		&juneauv1alpha1.NetworkEndpointAttachment{Ifindex: 1, ContainerID: "container-s1"})
	secondary := newProbeEndpoint("pod-a.1net", "pod-uid-1", "1net", "10.1.0.1/24",
		&juneauv1alpha1.NetworkEndpointAttachment{Ifindex: 3, ContainerID: "container-other"})

	proxy := NewServer(newRecoveryClient(t, pod, primary, secondary), "", pinNetNSDir(t, "pod-uid-1"))
	if err := proxy.Recover(context.Background(), "node-a"); err != nil {
		t.Fatalf("recover: %v", err)
	}

	if got := proxy.targets["ready"].host; got != "10.0.0.1" {
		t.Fatalf("recovered host = %q, want the primary interface address", got)
	}
	if got := proxy.containerIDs["pod-uid-1"]; got != "container-s1" {
		t.Fatalf("recovered container ID = %q, want the primary interface generation", got)
	}
}

func TestRecoverRejectsMalformedEndpointAddress(t *testing.T) {
	configs := probeconfig.Configs{"ready": {Type: "tcp", Port: 80, Timeout: 1}}
	pod := newProbePod(t, "pod-uid-1", configs)
	broken := newProbeEndpoint("pod-a.eth0", "pod-uid-1", "eth0", "not-a-cidr",
		&juneauv1alpha1.NetworkEndpointAttachment{Ifindex: 1, ContainerID: "container-s1"})

	proxy := NewServer(newRecoveryClient(t, pod, broken), "", pinNetNSDir(t, "pod-uid-1"))
	err := proxy.Recover(context.Background(), "node-a")
	if err == nil {
		t.Fatal("expected an error for an endpoint address that cannot be parsed")
	}
	if !strings.Contains(err.Error(), "not-a-cidr") {
		t.Fatalf("error must name the address it could not parse, got %v", err)
	}
}

func TestRecoverSkipsPodWithoutPinnedNamespace(t *testing.T) {
	configs := probeconfig.Configs{"ready": {Type: "tcp", Port: 80, Timeout: 1}}
	pod := newProbePod(t, "pod-uid-1", configs)
	endpoint := newProbeEndpoint("pod-a.eth0", "pod-uid-1", "eth0", "10.0.0.1/24",
		&juneauv1alpha1.NetworkEndpointAttachment{Ifindex: 1, ContainerID: "container-s1"})

	proxy := NewServer(newRecoveryClient(t, pod, endpoint), "", t.TempDir())
	if err := proxy.Recover(context.Background(), "node-a"); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if _, exists := proxy.targets["ready"]; exists {
		t.Fatal("published a target for a Pod with no pinned namespace")
	}
}
