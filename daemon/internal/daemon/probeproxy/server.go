package probeproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	probeconfig "github.com/1outres/juneau/controller/pkg/probe"
	"github.com/containernetworking/plugins/pkg/ns"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	DefaultBindAddress = "127.0.0.1:9911"
	DefaultNetNSDir    = "/var/run/juneau/netns"
	maxErrorBody       = 1024
	maxConcurrency     = 128
)

type target struct {
	podUID    string
	netnsPath string
	host      string
	config    probeconfig.Config
}

// Server is a node-local bridge between native kubelet HTTP probes and the
// original network probe executed inside a Juneau Pod's network namespace.
type Server struct {
	client   client.Client
	bind     string
	netnsDir string

	mu      sync.RWMutex
	targets map[string]target
	pods    map[string][]string
	limit   chan struct{}
}

func NewServer(cl client.Client, bind, netnsDir string) *Server {
	if bind == "" {
		bind = DefaultBindAddress
	}
	if netnsDir == "" {
		netnsDir = DefaultNetNSDir
	}
	return &Server{
		client: cl, bind: bind, netnsDir: netnsDir,
		targets: make(map[string]target), pods: make(map[string][]string),
		limit: make(chan struct{}, maxConcurrency),
	}
}

func (s *Server) Run(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.bind)
	if err != nil {
		return fmt.Errorf("listen for node-local probes on %s: %w", s.bind, err)
	}
	server := &http.Server{Handler: s, ReadHeaderTimeout: 2 * time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown probe proxy: %w", err)
		}
		err := <-done
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// RegisterPod is called synchronously by CNI ADD after networking is ready.
// It pins the namespace before publishing token mappings, so kubelet cannot
// observe a target whose namespace is unavailable.
func (s *Server) RegisterPod(ctx context.Context, namespace, name, uid, netnsPath, address string) error {
	if !validUID(uid) {
		return fmt.Errorf("invalid Pod UID %q", uid)
	}
	var pod corev1.Pod
	if err := s.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &pod); err != nil {
		return fmt.Errorf("get Pod probe configuration: %w", err)
	}
	if string(pod.UID) != uid {
		return fmt.Errorf("pod UID changed from %q to %q", uid, pod.UID)
	}
	if pod.Annotations[probeconfig.AnnotationRewriteVersion] == "" {
		return nil
	}
	if pod.Annotations[probeconfig.AnnotationRewriteVersion] != probeconfig.RewriteVersion {
		return fmt.Errorf("unsupported probe rewrite version %q", pod.Annotations[probeconfig.AnnotationRewriteVersion])
	}
	configs, err := probeconfig.Parse(pod.Annotations[probeconfig.AnnotationConfigs])
	if err != nil {
		return err
	}
	if len(configs) == 0 {
		return fmt.Errorf("rewritten Pod has no probe configs")
	}
	host, _, err := net.ParseCIDR(address)
	if err != nil {
		return fmt.Errorf("parse Pod address %q: %w", address, err)
	}
	pinned, err := s.pinNetNS(uid, netnsPath)
	if err != nil {
		return err
	}
	if err := s.publish(uid, pinned, host.String(), configs); err != nil {
		_ = s.unpinNetNS(uid)
		return err
	}
	return nil
}

func (s *Server) publish(uid, netnsPath, host string, configs probeconfig.Configs) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for token := range configs {
		if existing, ok := s.targets[token]; ok && existing.podUID != uid {
			return fmt.Errorf("probe token collision")
		}
	}
	s.removePodLocked(uid)
	tokens := make([]string, 0, len(configs))
	for token, config := range configs {
		s.targets[token] = target{podUID: uid, netnsPath: netnsPath, host: host, config: config}
		tokens = append(tokens, token)
	}
	s.pods[uid] = tokens
	return nil
}

// Recover rebuilds token mappings after a daemon restart from the pinned
// namespaces, local Pods, and their NetworkEndpoints. Stale pins are removed.
func (s *Server) Recover(ctx context.Context, nodeName string) error {
	var pods corev1.PodList
	// The daemon cache is already scoped to this node by its Pod field selector.
	// Listing the cache directly avoids requiring a second client-side field index.
	if err := s.client.List(ctx, &pods); err != nil {
		return fmt.Errorf("list local Pods for probe recovery: %w", err)
	}
	active := make(map[string]struct{})
	for i := range pods.Items {
		pod := &pods.Items[i]
		uid := string(pod.UID)
		if pod.Annotations[probeconfig.AnnotationRewriteVersion] != probeconfig.RewriteVersion {
			continue
		}
		configs, err := probeconfig.Parse(pod.Annotations[probeconfig.AnnotationConfigs])
		if err != nil {
			return fmt.Errorf("recover Pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}
		pin := filepath.Join(s.netnsDir, uid)
		if _, err := os.Stat(pin); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return fmt.Errorf("stat netns pin for Pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}
		var endpoints juneauv1alpha1.NetworkEndpointList
		if err := s.client.List(ctx, &endpoints, client.InNamespace(pod.Namespace), client.MatchingFields{
			"spec.podRef.uid": uid,
		}); err != nil {
			return fmt.Errorf("list NetworkEndpoints for Pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}
		var address string
		for j := range endpoints.Items {
			endpoint := &endpoints.Items[j]
			if endpoint.Spec.NodeName == nodeName && endpoint.Spec.PodRef != nil && endpoint.Spec.PodRef.Interface == "eth0" {
				address = endpoint.Spec.Address
				break
			}
		}
		host, _, err := net.ParseCIDR(address)
		if err != nil {
			continue
		}
		if err := s.publish(uid, pin, host.String(), configs); err != nil {
			return fmt.Errorf("recover Pod %s/%s probes: %w", pod.Namespace, pod.Name, err)
		}
		active[uid] = struct{}{}
	}
	entries, err := os.ReadDir(s.netnsDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("list netns pins: %w", err)
	}
	for _, entry := range entries {
		if _, ok := active[entry.Name()]; ok {
			continue
		}
		if err := s.UnregisterPod(entry.Name()); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) UnregisterPod(uid string) error {
	if uid == "" {
		return nil
	}
	if !validUID(uid) {
		return fmt.Errorf("invalid Pod UID %q", uid)
	}
	s.mu.Lock()
	s.removePodLocked(uid)
	s.mu.Unlock()
	return s.unpinNetNS(uid)
}

func (s *Server) removePodLocked(uid string) {
	for _, token := range s.pods[uid] {
		delete(s.targets, token)
	}
	delete(s.pods, uid)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, probeconfig.EndpointPathPrefix) {
		http.NotFound(w, r)
		return
	}
	token := strings.TrimPrefix(r.URL.Path, probeconfig.EndpointPathPrefix)
	if token == "" || strings.Contains(token, "/") {
		http.NotFound(w, r)
		return
	}
	s.mu.RLock()
	target, ok := s.targets[token]
	s.mu.RUnlock()
	if !ok {
		http.Error(w, "probe target is not registered", http.StatusServiceUnavailable)
		return
	}
	select {
	case s.limit <- struct{}{}:
		defer func() { <-s.limit }()
	case <-r.Context().Done():
		return
	}
	if err := s.execute(r.Context(), target); err != nil {
		message := err.Error()
		if len(message) > maxErrorBody {
			message = message[:maxErrorBody]
		}
		http.Error(w, message, http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) execute(parent context.Context, target target) error {
	netns, err := ns.GetNS(target.netnsPath)
	if err != nil {
		return fmt.Errorf("open Pod network namespace: %w", err)
	}
	defer func() { _ = netns.Close() }()
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		var conn net.Conn
		var dialErr error
		if err := netns.Do(func(_ ns.NetNS) error {
			conn, dialErr = (&net.Dialer{}).DialContext(ctx, network, address)
			return dialErr
		}); err != nil {
			return nil, err
		}
		return conn, nil
	}
	return executeWithDial(parent, target, dial)
}

func executeWithDial(parent context.Context, target target, dial func(context.Context, string, string) (net.Conn, error)) error {
	timeout := time.Duration(target.config.Timeout) * time.Second
	if timeout <= 0 {
		timeout = time.Second
	}
	if timeout > 200*time.Millisecond {
		timeout -= 100 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	switch target.config.Type {
	case "tcp":
		conn, err := dial(ctx, "tcp", target.address())
		if err != nil {
			return err
		}
		return conn.Close()
	case "http":
		return probeHTTP(ctx, target, dial)
	case "grpc":
		return probeGRPC(ctx, target, dial)
	default:
		return fmt.Errorf("unsupported probe type %q", target.config.Type)
	}
}

func (t target) address() string {
	return net.JoinHostPort(t.host, strconv.Itoa(int(t.config.Port)))
}

func probeHTTP(ctx context.Context, target target, dial func(context.Context, string, string) (net.Conn, error)) error {
	scheme := strings.ToLower(target.config.Scheme)
	if scheme == "" {
		scheme = "http"
	}
	path := target.config.Path
	if path == "" {
		path = "/"
	}
	requestURI, err := url.ParseRequestURI(path)
	if err != nil {
		return fmt.Errorf("parse HTTP probe path: %w", err)
	}
	requestURL := url.URL{Scheme: scheme, Host: target.address(), Path: requestURI.Path, RawQuery: requestURI.RawQuery}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return err
	}
	hasUserAgent, hasAccept := false, false
	for _, header := range target.config.Headers {
		if strings.EqualFold(header.Name, "Host") {
			request.Host = header.Value
			continue
		}
		request.Header.Add(header.Name, header.Value)
		hasUserAgent = hasUserAgent || strings.EqualFold(header.Name, "User-Agent")
		hasAccept = hasAccept || strings.EqualFold(header.Name, "Accept")
	}
	if !hasUserAgent {
		request.Header.Set("User-Agent", "kube-probe/juneau")
	}
	if !hasAccept {
		request.Header.Set("Accept", "*/*")
	}
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, DisableCompression: true, ForceAttemptHTTP2: true, DialContext: dial,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Kubernetes probe semantics.
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(next *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		if len(via) > 0 && next.URL.Hostname() != via[0].URL.Hostname() {
			return http.ErrUseLastResponse
		}
		return nil
	}}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 10<<10))
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("HTTP status %d", response.StatusCode)
	}
	return nil
}

func probeGRPC(ctx context.Context, target target, dial func(context.Context, string, string) (net.Conn, error)) error {
	grpcDial := func(ctx context.Context, address string) (net.Conn, error) {
		return dial(ctx, "tcp", address)
	}
	conn, err := grpc.NewClient(target.address(), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(grpcDial))
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	response, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{Service: target.config.GRPCService})
	if err != nil {
		return err
	}
	if response.Status != healthpb.HealthCheckResponse_SERVING {
		return fmt.Errorf("service status is %s", response.Status.String())
	}
	return nil
}

func (s *Server) pinNetNS(uid, source string) (string, error) {
	if err := os.MkdirAll(s.netnsDir, 0o700); err != nil {
		return "", fmt.Errorf("create netns pin directory: %w", err)
	}
	target := filepath.Join(s.netnsDir, uid)
	file, err := os.OpenFile(target, os.O_CREATE|os.O_RDONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("create netns pin: %w", err)
	}
	_ = file.Close()
	_ = unix.Unmount(target, unix.MNT_DETACH)
	if err := unix.Mount(source, target, "", unix.MS_BIND, ""); err != nil {
		_ = os.Remove(target)
		return "", fmt.Errorf("pin Pod network namespace: %w", err)
	}
	return target, nil
}

func (s *Server) unpinNetNS(uid string) error {
	target := filepath.Join(s.netnsDir, uid)
	err := unix.Unmount(target, unix.MNT_DETACH)
	if err != nil && !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("unpin Pod network namespace: %w", err)
	}
	if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove netns pin: %w", err)
	}
	return nil
}

func validUID(uid string) bool {
	return uid != "" && uid != "." && uid != ".." && filepath.Base(uid) == uid && !strings.ContainsAny(uid, `/\\`)
}
