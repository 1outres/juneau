package nodeagent

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/1outres/juneau/daemon/pkg/debugpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

// PortForwardDialerOptions configures the portforward-backed Dialer.
//
// Defaults match the daemon DaemonSet shipped under
// daemon/config/default. Operators with custom labels / namespaces
// override them at Factory construction time.
type PortForwardDialerOptions struct {
	// Namespace the daemon DaemonSet runs in.
	Namespace string
	// LabelSelector for the daemon Pod on a given node.
	LabelSelector string
	// DaemonDebugPort is the TCP port the daemon binds its Debug
	// gRPC service on, inside the Pod's network namespace.
	DaemonDebugPort uint16
	// DialTimeout bounds the portforward setup phase.
	DialTimeout time.Duration
}

func (o PortForwardDialerOptions) namespace() string {
	if o.Namespace == "" {
		return "kube-system"
	}
	return o.Namespace
}

func (o PortForwardDialerOptions) labelSelector() string {
	if o.LabelSelector == "" {
		return "app=cni-daemon"
	}
	return o.LabelSelector
}

func (o PortForwardDialerOptions) daemonDebugPort() uint16 {
	if o.DaemonDebugPort == 0 {
		return 9089 // matches grpc.DefaultDebugTCPAddr
	}
	return o.DaemonDebugPort
}

func (o PortForwardDialerOptions) dialTimeout() time.Duration {
	if o.DialTimeout <= 0 {
		return 10 * time.Second
	}
	return o.DialTimeout
}

// NewPortForwardDialer constructs a Dialer that tunnels gRPC traffic
// over `kubectl port-forward` to the daemon's localhost-bound Debug
// listener.
//
// Compared to the older exec-tunnel transport this:
//   - uses the standard k8s.io/client-go portforward primitive
//     (HTTP/2 stream multiplex over SPDY) — no custom net.Conn shim;
//   - requires only `pods/portforward` RBAC instead of `pods/exec`;
//   - lets gRPC's HTTP/2 multiplex span the full session (multiple
//     concurrent RPCs share one tunnel).
func NewPortForwardDialer(cfg *rest.Config, kube kubernetes.Interface, streams genericiooptions.IOStreams, opts PortForwardDialerOptions) Dialer {
	return &pfDialer{cfg: cfg, kube: kube, streams: streams, opts: opts}
}

type pfDialer struct {
	cfg     *rest.Config
	kube    kubernetes.Interface
	streams genericiooptions.IOStreams
	opts    PortForwardDialerOptions
}

func (d *pfDialer) Dial(ctx context.Context, node string) (Client, error) {
	pod, err := d.findDaemonPod(ctx, node)
	if err != nil {
		return nil, err
	}

	pf, localPort, err := d.startPortForward(ctx, pod.Namespace, pod.Name)
	if err != nil {
		return nil, err
	}

	dialCtx, cancel := context.WithTimeout(ctx, d.opts.dialTimeout())
	defer cancel()
	conn, err := grpc.DialContext(dialCtx,
		"127.0.0.1:"+strconv.Itoa(int(localPort)),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		pf.Close()
		return nil, fmt.Errorf("nodeagent: dial portforwarded gRPC: %w", err)
	}
	return &pfClient{conn: conn, debug: debugpb.NewDebugClient(conn), pf: pf}, nil
}

func (d *pfDialer) findDaemonPod(ctx context.Context, node string) (*corev1.Pod, error) {
	pods, err := d.kube.CoreV1().Pods(d.opts.namespace()).List(ctx, metav1.ListOptions{
		LabelSelector: d.opts.labelSelector(),
		FieldSelector: "spec.nodeName=" + node,
	})
	if err != nil {
		if apierrors.IsForbidden(err) {
			return nil, fmt.Errorf("nodeagent: list daemon pods (%s/%s): %w", d.opts.namespace(), d.opts.labelSelector(), err)
		}
		return nil, fmt.Errorf("nodeagent: list daemon pods: %w", err)
	}
	if len(pods.Items) == 0 {
		return nil, fmt.Errorf("nodeagent: no daemon pod on node %q (namespace=%s, selector=%s)", node, d.opts.namespace(), d.opts.labelSelector())
	}
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.Status.Phase == corev1.PodRunning {
			return p, nil
		}
	}
	return nil, fmt.Errorf("nodeagent: no Running daemon pod on node %q", node)
}

// startPortForward sets up a port-forward session against the
// daemon Pod's debug TCP port and returns a forwarder handle plus
// the locally-bound port number gRPC should dial. The forwarder
// runs on a background goroutine until handle.Close is called.
func (d *pfDialer) startPortForward(ctx context.Context, namespace, podName string) (*portForwardHandle, uint16, error) {
	roundTripper, upgrader, err := spdy.RoundTripperFor(d.cfg)
	if err != nil {
		return nil, 0, fmt.Errorf("nodeagent: spdy roundtripper: %w", err)
	}
	pfURL := d.kube.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("portforward").
		URL()

	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: roundTripper}, "POST", pfURL)
	stop := make(chan struct{})
	ready := make(chan struct{})
	ports := []string{fmt.Sprintf("0:%d", d.opts.daemonDebugPort())}

	// portforward.NewOnAddresses logs "Forwarding from 127.0.0.1:N
	// -> N" and "Handling connection for N" on every connection.
	// Useful when running `kubectl port-forward` interactively, but
	// it pollutes our trace timeline. Discard the informational
	// stream; real errors still flow to ErrOut.
	pf, err := portforward.NewOnAddresses(dialer, []string{"127.0.0.1"}, ports, stop, ready, io.Discard, d.streams.ErrOut)
	if err != nil {
		return nil, 0, fmt.Errorf("nodeagent: portforward construct: %w", err)
	}

	errCh := make(chan error, 1)
	go func() { errCh <- pf.ForwardPorts() }()

	select {
	case <-ready:
	case err := <-errCh:
		return nil, 0, fmt.Errorf("nodeagent: portforward setup: %w", err)
	case <-time.After(d.opts.dialTimeout()):
		close(stop)
		return nil, 0, fmt.Errorf("nodeagent: portforward setup timed out after %s", d.opts.dialTimeout())
	case <-ctx.Done():
		close(stop)
		return nil, 0, ctx.Err()
	}

	bound, err := pf.GetPorts()
	if err != nil {
		close(stop)
		return nil, 0, fmt.Errorf("nodeagent: portforward GetPorts: %w", err)
	}
	if len(bound) == 0 {
		close(stop)
		return nil, 0, fmt.Errorf("nodeagent: portforward returned no ports")
	}
	return &portForwardHandle{stop: stop, pf: pf, errCh: errCh}, bound[0].Local, nil
}

type portForwardHandle struct {
	stop  chan struct{}
	pf    *portforward.PortForwarder
	errCh chan error
}

// Close terminates the portforward stream by closing its stop
// channel; the background ForwardPorts goroutine exits and pushes a
// (possibly nil) result onto errCh. We drain errCh so the goroutine
// does not leak.
func (h *portForwardHandle) Close() {
	if h == nil {
		return
	}
	select {
	case <-h.stop:
		// already closed
	default:
		close(h.stop)
	}
	// Drain background error best-effort; portforward emits nil on
	// clean shutdown.
	select {
	case <-h.errCh:
	case <-time.After(2 * time.Second):
	}
}

type pfClient struct {
	conn  *grpc.ClientConn
	debug debugpb.DebugClient
	pf    *portForwardHandle
}

func (c *pfClient) Debug() debugpb.DebugClient { return c.debug }
func (c *pfClient) Close() error {
	err := c.conn.Close()
	c.pf.Close()
	return err
}

// asURL is here only to keep client-go's url package referenced under
// some build configurations; the import is needed by RoundTripperFor.
var _ = url.URL{}

// Compile-time conformance.
var (
	_ Client = (*pfClient)(nil)
	_ Dialer = (*pfDialer)(nil)
)
