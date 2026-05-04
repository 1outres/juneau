package nodeagent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/1outres/juneau/daemon/pkg/debugpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

// ExecDialerOptions tunes how the exec-tunnel dialer locates
// daemon Pods.
type ExecDialerOptions struct {
	// Namespace is the namespace the daemon DaemonSet runs in.
	// Defaults to "kube-system" when empty.
	Namespace string
	// LabelSelector picks the daemon Pod on a given node. The Pod is
	// further filtered by .spec.nodeName == node.
	LabelSelector string
	// RelayCommand is the argv the dialer execs inside the daemon
	// Pod to bridge stdio to the daemon's unix socket. The default
	// uses `juneaud relay <uds>` so the bridge ships in the same
	// binary that runs the daemon.
	RelayCommand []string
	// UDSPath is the daemon's gRPC unix socket inside the Pod.
	UDSPath string
	// DialTimeout bounds the exec setup phase.
	DialTimeout time.Duration
}

func (o ExecDialerOptions) namespace() string {
	if o.Namespace == "" {
		return "kube-system"
	}
	return o.Namespace
}

func (o ExecDialerOptions) labelSelector() string {
	if o.LabelSelector == "" {
		// Match the default daemonset label produced by the daemon
		// chart (config/default/daemon.yaml sets "app: cni-daemon");
		// operators with custom labels override this.
		return "app=cni-daemon"
	}
	return o.LabelSelector
}

func (o ExecDialerOptions) relayCommand(udsPath string) []string {
	if len(o.RelayCommand) > 0 {
		return o.RelayCommand
	}
	return []string{"/juneaud", "relay", udsPath}
}

func (o ExecDialerOptions) udsPath() string {
	if o.UDSPath == "" {
		return "/var/run/juneaud.sock"
	}
	return o.UDSPath
}

func (o ExecDialerOptions) dialTimeout() time.Duration {
	if o.DialTimeout <= 0 {
		return 10 * time.Second
	}
	return o.DialTimeout
}

// NewExecDialer constructs a Dialer that tunnels gRPC traffic via
// `kubectl exec` into the per-Node daemon Pod. Exec is the lowest-
// privilege transport that works without exposing a network port on
// every Node and reuses kubectl RBAC.
func NewExecDialer(cfg *rest.Config, kube kubernetes.Interface, streams genericiooptions.IOStreams, opts ExecDialerOptions) Dialer {
	return &execDialer{cfg: cfg, kube: kube, streams: streams, opts: opts}
}

type execDialer struct {
	cfg     *rest.Config
	kube    kubernetes.Interface
	streams genericiooptions.IOStreams
	opts    ExecDialerOptions
}

func (d *execDialer) Dial(ctx context.Context, node string) (Client, error) {
	pod, err := d.findDaemonPod(ctx, node)
	if err != nil {
		return nil, err
	}
	conn, err := d.dialExec(ctx, pod.Namespace, pod.Name)
	if err != nil {
		return nil, err
	}
	return &execClient{conn: conn, debug: debugpb.NewDebugClient(conn)}, nil
}

func (d *execDialer) findDaemonPod(ctx context.Context, node string) (*corev1.Pod, error) {
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

func (d *execDialer) dialExec(ctx context.Context, namespace, podName string) (*grpc.ClientConn, error) {
	dialer := func(_ context.Context, _ string) (net.Conn, error) {
		req := d.kube.CoreV1().RESTClient().Post().
			Resource("pods").
			Name(podName).
			Namespace(namespace).
			SubResource("exec").
			VersionedParams(&corev1.PodExecOptions{
				Command: d.opts.relayCommand(d.opts.udsPath()),
				Stdin:   true,
				Stdout:  true,
				Stderr:  true,
				TTY:     false,
			}, scheme.ParameterCodec)

		exec, err := remotecommand.NewSPDYExecutor(d.cfg, "POST", req.URL())
		if err != nil {
			return nil, err
		}
		return newExecConn(ctx, exec, namespace, podName), nil
	}

	dialCtx, cancel := context.WithTimeout(ctx, d.opts.dialTimeout())
	defer cancel()

	return grpc.DialContext(dialCtx,
		"unix:" + d.opts.udsPath(),
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
}

type execClient struct {
	conn  *grpc.ClientConn
	debug debugpb.DebugClient
}

func (c *execClient) Debug() debugpb.DebugClient { return c.debug }
func (c *execClient) Close() error                { return c.conn.Close() }

// execConn implements net.Conn over a remotecommand.Executor's
// stdio streams. SPDY's stream multiplexing makes Stdin / Stdout one
// bidirectional virtual socket; gRPC just sees a net.Conn.
type execConn struct {
	stdinR  io.Reader
	stdinW  *io.PipeWriter
	stdoutR *io.PipeReader
	stdoutW *io.PipeWriter

	stderrR *io.PipeReader
	stderrW *io.PipeWriter

	doneCh chan struct{}
	errCh  chan error
}

func newExecConn(ctx context.Context, exec remotecommand.Executor, ns, name string) *execConn {
	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()
	stderrR, stderrW := io.Pipe()
	c := &execConn{
		stdinR:  stdinR,
		stdinW:  stdinW,
		stdoutR: stdoutR,
		stdoutW: stdoutW,
		stderrR: stderrR,
		stderrW: stderrW,
		doneCh:  make(chan struct{}),
		errCh:   make(chan error, 1),
	}

	go func() {
		defer close(c.doneCh)
		defer runtime.HandleCrash()
		err := exec.StreamWithContext(ctx, remotecommand.StreamOptions{
			Stdin:  stdinR,
			Stdout: stdoutW,
			Stderr: stderrW,
		})
		// Closing the writer ends the gRPC reader cleanly.
		_ = stdoutW.Close()
		_ = stderrW.Close()
		if err != nil {
			c.errCh <- fmt.Errorf("exec %s/%s: %w", ns, name, err)
			return
		}
		c.errCh <- nil
	}()

	// Drain stderr so socat / shell errors do not deadlock the pipe.
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := stderrR.Read(buf)
			if n > 0 {
				// Best-effort logging; no reliable way to surface
				// from inside a gRPC dialer. Drop silently.
				_ = buf[:n]
			}
			if err != nil {
				return
			}
		}
	}()

	return c
}

func (c *execConn) Read(b []byte) (int, error)  { return c.stdoutR.Read(b) }
func (c *execConn) Write(b []byte) (int, error) { return c.stdinW.Write(b) }
func (c *execConn) Close() error {
	err := c.stdinW.Close()
	<-c.doneCh
	if streamErr := <-c.errCh; streamErr != nil && !errors.Is(streamErr, io.EOF) {
		if err == nil {
			err = streamErr
		}
	}
	return err
}
func (c *execConn) LocalAddr() net.Addr                { return execAddr{} }
func (c *execConn) RemoteAddr() net.Addr               { return execAddr{} }
func (c *execConn) SetDeadline(time.Time) error        { return nil }
func (c *execConn) SetReadDeadline(time.Time) error    { return nil }
func (c *execConn) SetWriteDeadline(time.Time) error   { return nil }

type execAddr struct{}

func (execAddr) Network() string { return "exec" }
func (execAddr) String() string  { return "kubectl-exec" }

// Compile-time checks.
var (
	_ Client          = (*execClient)(nil)
	_ Dialer          = (*execDialer)(nil)
	_ net.Conn        = (*execConn)(nil)
	_ remotecommand.Executor = (remotecommand.Executor)(nil)
)

// extraneous keeps strings package linkable; trims a leading "/" on
// labels for nicer error messages elsewhere.
var _ = strings.TrimSpace
