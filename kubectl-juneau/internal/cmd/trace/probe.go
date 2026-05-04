package trace

import (
	"context"
	"fmt"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

// driveProbe runs the active probe step when the user asked for one.
// ObserveOnly mode is a no-op. The pod-exec strategy execs a small
// command inside the source Pod that generates a single TCP / UDP /
// ICMP packet matching the destination tuple; daemon-side strategies
// are stubbed to return cleanly until the daemon implements them.
//
// Errors are written to stderr and never abort the run loop — the
// trace command can still surface useful information from existing
// traffic even if probe injection fails.
func (o *Options) driveProbe(ctx context.Context, r *resolved) {
	if o.ObserveOnly {
		return
	}
	if o.ProbeKind != "pod-exec" {
		fmt.Fprintf(o.Factory.Streams().ErrOut,
			"trace: probe strategy %q is not implemented in this build (use --observe-only to suppress)\n",
			o.ProbeKind)
		return
	}
	if r.source.pod == nil || !r.destination.ip.IsValid() {
		fmt.Fprintln(o.Factory.Streams().ErrOut,
			"trace: pod-exec probe requires a Pod source and resolvable destination")
		return
	}

	cfg, err := o.Factory.RESTConfig()
	if err != nil {
		fmt.Fprintf(o.Factory.Streams().ErrOut, "trace: probe rest config: %v\n", err)
		return
	}
	kc, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		fmt.Fprintf(o.Factory.Streams().ErrOut, "trace: probe kube client: %v\n", err)
		return
	}

	cmd, err := o.buildProbeCommand(r)
	if err != nil {
		fmt.Fprintf(o.Factory.Streams().ErrOut, "trace: build probe command: %v\n", err)
		return
	}

	// Wait briefly for daemons to program BPF state before sending —
	// otherwise the first packet will not be classified.
	select {
	case <-ctx.Done():
		return
	case <-time.After(500 * time.Millisecond):
	}

	req := kc.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(r.source.pod.Name).
		Namespace(r.source.pod.Namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Command: cmd,
			Stdin:   false,
			Stdout:  true,
			Stderr:  true,
			TTY:     false,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(cfg, "POST", req.URL())
	if err != nil {
		fmt.Fprintf(o.Factory.Streams().ErrOut, "trace: probe exec setup: %v\n", err)
		return
	}
	streams := o.Factory.Streams()
	if err := exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: nullWriter(streams),
		Stderr: streams.ErrOut,
	}); err != nil {
		fmt.Fprintf(streams.ErrOut, "trace: probe exec: %v\n", err)
	}
}

// buildProbeCommand returns the argv to run inside the Pod for one
// shot. Probes are intentionally minimal — they need only to flip an
// L3/L4 packet onto the wire so the dataplane sees it. Stdout from
// the probe is suppressed so trace's own timeline stays the focal
// point of the output.
func (o *Options) buildProbeCommand(r *resolved) ([]string, error) {
	dst := r.destination.ip.String()
	port := strconv.FormatInt(int64(o.Port), 10)
	switch o.crdProtocol() {
	case "TCP":
		// `nc -z` is widely available in alpine-based images; for
		// distroless / scratch images the operator must use
		// observe-only mode.
		return []string{"sh", "-c",
			fmt.Sprintf("nc -z -w 2 %s %s 2>/dev/null || true", dst, port),
		}, nil
	case "UDP":
		// Send a single byte; the lack of a reply is fine — we just
		// want one packet on the wire.
		return []string{"sh", "-c",
			fmt.Sprintf("printf x | nc -u -w 1 %s %s 2>/dev/null || true", dst, port),
		}, nil
	case "ICMP":
		return []string{"sh", "-c",
			fmt.Sprintf("ping -c 1 -W 1 %s 2>/dev/null || true", dst),
		}, nil
	}
	return nil, fmt.Errorf("unsupported protocol %q", o.Protocol)
}

// nullWriter discards probe stdout so it does not interleave with
// the timeline. ErrOut is preserved so probe failures still surface.
func nullWriter(streams genericiooptions.IOStreams) *discardWriter {
	return &discardWriter{}
}

type discardWriter struct{}

func (*discardWriter) Write(b []byte) (int, error) { return len(b), nil }
