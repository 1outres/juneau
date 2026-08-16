package probeproxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	probeconfig "github.com/1outres/juneau/controller/pkg/probe"
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
	if err := proxy.publish("first", "/first", "10.0.0.1", first); err != nil {
		t.Fatal(err)
	}
	if err := proxy.publish("second", "/second", "10.0.0.2", probeconfig.Configs{
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
