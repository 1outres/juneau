package trace

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/kubectl-juneau/internal/factory"
)

// Options is the parsed flag/argument state for the trace command.
//
// Following the kubectl idiom: Complete pulls implicit values
// (namespace from kubeconfig, default capture flags, fresh trace
// ID), Validate enforces invariants the flag wiring cannot, and Run
// performs the work. Tests substitute a fake Factory and call the
// methods directly.
type Options struct {
	Factory factory.Factory

	// Source / destination flags.
	SourcePod string // namespace/name
	SourceIP  string
	// SourceInterface names which NIC of SourcePod the trace is about.
	// Empty means the Pod's own address on its primary NIC.
	SourceInterface string
	DestPod         string // namespace/name
	DestService     string // namespace/name
	DestIP          string
	DestInterface   string

	Protocol string
	Port     int32

	// Capture / mode.
	ObserveOnly   bool
	ProbeKind     string // pod-exec | daemon-netns | daemon-host
	CaptureLevel  string // summary | decision | verbose
	IncludeMeta   bool
	IncludeMisses bool
	IncludePolicy bool
	IncludeNAT    bool

	// Lifecycle.
	Timeout      time.Duration
	TTL          time.Duration
	KeepSession  bool
	OutputFile   string
	OutputFormat string

	// Resolved / derived state. Populated by Complete.
	sourceNamespace string
	destNamespace   string
	traceID         uint32
}

func newOptions(f factory.Factory) *Options {
	return &Options{
		Factory:       f,
		Protocol:      "tcp",
		ObserveOnly:   false,
		ProbeKind:     "pod-exec",
		CaptureLevel:  "decision",
		IncludeMisses: true,
		IncludePolicy: true,
		IncludeNAT:    true,
		Timeout:       10 * time.Second,
		TTL:           30 * time.Second,
		OutputFormat:  "tree",
	}
}

// AddFlags wires the options onto cobra.
func (o *Options) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.SourcePod, "from-pod", "", "Source Pod (namespace/name).")
	cmd.Flags().StringVar(&o.SourceIP, "from-ip", "", "Source IPv4. On its own it traces a raw address; with --from-pod it says which address of that Pod to trace.")
	cmd.Flags().StringVar(&o.SourceInterface, "interface", "", "NIC of --from-pod to trace (default: the Pod's primary NIC).")

	cmd.Flags().StringVar(&o.DestPod, "to-pod", "", "Destination Pod (namespace/name).")
	cmd.Flags().StringVar(&o.DestService, "to-service", "", "Destination Service (namespace/name).")
	cmd.Flags().StringVar(&o.DestIP, "to-ip", "", "Destination IPv4. On its own it traces a raw address; with --to-pod it says which address of that Pod to trace.")
	cmd.Flags().StringVar(&o.DestInterface, "to-interface", "", "NIC of --to-pod to trace (default: the Pod's primary NIC).")

	cmd.Flags().StringVar(&o.Protocol, "proto", o.Protocol, "L4 protocol (tcp|udp|icmp).")
	cmd.Flags().Int32Var(&o.Port, "port", o.Port, "Destination L4 port (required for tcp/udp).")

	cmd.Flags().BoolVar(&o.ObserveOnly, "observe-only", o.ObserveOnly, "Do not inject probe traffic; observe matching packets only.")
	cmd.Flags().StringVar(&o.ProbeKind, "probe", o.ProbeKind, "Probe injection strategy (pod-exec|daemon-netns|daemon-host).")
	cmd.Flags().StringVar(&o.CaptureLevel, "capture", o.CaptureLevel, "Capture verbosity (summary|decision|verbose).")
	cmd.Flags().BoolVar(&o.IncludeMeta, "include-meta", o.IncludeMeta, "Include packet metadata (TCP flags, ICMP type/code) in events.")
	cmd.Flags().BoolVar(&o.IncludeMisses, "include-map-miss", o.IncludeMisses, "Emit map-miss events.")
	cmd.Flags().BoolVar(&o.IncludePolicy, "include-policy", o.IncludePolicy, "Emit policy verdict events.")
	cmd.Flags().BoolVar(&o.IncludeNAT, "include-nat", o.IncludeNAT, "Emit NAT before/after tuple events.")

	cmd.Flags().DurationVar(&o.Timeout, "timeout", o.Timeout, "Maximum time to wait for events (active probe) or watch traffic (observe-only).")
	cmd.Flags().DurationVar(&o.TTL, "ttl", o.TTL, "TraceSession.spec.expiresAt offset from now. Daemons drop session state after this even if kubectl crashes.")
	cmd.Flags().BoolVar(&o.KeepSession, "keep-session", o.KeepSession, "Do not delete the TraceSession on exit.")
	cmd.Flags().StringVar(&o.OutputFile, "output-file", o.OutputFile, "Append decoded events to this file as newline-delimited JSON.")
	cmd.Flags().StringVarP(&o.OutputFormat, "output", "o", o.OutputFormat, "Output format (tree|json|yaml).")
}

// Complete fills in derived values. Positional args provide a quick
// shorthand: `trace pod ns/name --to service ns/name` is equivalent
// to `--from-pod ns/name --to-service ns/name`.
func (o *Options) Complete(args []string) error {
	if len(args) >= 2 {
		switch args[0] {
		case "pod":
			if o.SourcePod == "" {
				o.SourcePod = args[1]
			}
		case "ip":
			if o.SourceIP == "" {
				o.SourceIP = args[1]
			}
		default:
			return fmt.Errorf("unrecognised positional %q (expected pod|ip)", args[0])
		}
	}

	defaultNs, _, err := o.Factory.Namespace()
	if err != nil {
		return err
	}
	o.sourceNamespace = defaultNs
	o.destNamespace = defaultNs

	if o.SourcePod != "" {
		ns, name := splitNamespacedName(o.SourcePod, defaultNs)
		o.SourcePod = ns + "/" + name
		o.sourceNamespace = ns
	}
	if o.DestPod != "" {
		ns, name := splitNamespacedName(o.DestPod, defaultNs)
		o.DestPod = ns + "/" + name
		o.destNamespace = ns
	}
	if o.DestService != "" {
		ns, name := splitNamespacedName(o.DestService, defaultNs)
		o.DestService = ns + "/" + name
	}

	o.traceID = randomTraceID()
	return nil
}

// Validate enforces invariants the cobra flags themselves cannot
// express. Failures here happen before any cluster I/O.
// A Pod and an address may be given together on either side. The Pod
// says which network the trace is scoped to and where to inject the
// probe; the address says which of that Pod's addresses to follow. An
// L2Network without a CIDR needs both, because juneau hands out no
// address there and never learns the one the workload picked.
func (o *Options) Validate() error {
	if o.SourcePod == "" && o.SourceIP == "" {
		return fmt.Errorf("--from-pod or --from-ip is required")
	}
	if o.SourceInterface != "" && o.SourcePod == "" {
		return fmt.Errorf("--interface names a NIC of --from-pod, so --from-pod is required with it")
	}

	if o.DestPod != "" && o.DestService != "" {
		return fmt.Errorf("--to-pod and --to-service name two different destinations; pick one")
	}
	// A Service is reached at its ClusterIP, and the backend addresses
	// are read off its EndpointSlices. There is no address left for the
	// user to choose.
	if o.DestService != "" && o.DestIP != "" {
		return fmt.Errorf("--to-service already says which address to trace, so --to-ip cannot be given with it")
	}
	if o.DestPod == "" && o.DestService == "" && o.DestIP == "" {
		return fmt.Errorf("one of --to-pod / --to-service / --to-ip is required")
	}
	if o.DestInterface != "" && o.DestPod == "" {
		return fmt.Errorf("--to-interface names a NIC of --to-pod, so --to-pod is required with it")
	}

	switch strings.ToLower(o.Protocol) {
	case "tcp", "udp":
		if o.Port <= 0 {
			return fmt.Errorf("--port is required for tcp/udp")
		}
		if o.Port > 65535 {
			return fmt.Errorf("--port must fit in [1,65535]")
		}
	case "icmp":
		if o.Port != 0 {
			return fmt.Errorf("--port must not be set for icmp")
		}
	default:
		return fmt.Errorf("--proto must be one of tcp|udp|icmp")
	}

	switch strings.ToLower(o.CaptureLevel) {
	case "summary", "decision", "verbose":
	default:
		return fmt.Errorf("--capture must be one of summary|decision|verbose")
	}

	if !o.ObserveOnly {
		switch o.ProbeKind {
		case "pod-exec":
			if o.SourcePod == "" {
				return fmt.Errorf("probe=pod-exec requires --from-pod")
			}
		case "daemon-netns", "daemon-host":
			// Future strategies; daemon-side support gated.
		default:
			return fmt.Errorf("--probe must be one of pod-exec|daemon-netns|daemon-host")
		}
	}

	if o.TTL <= 0 {
		return fmt.Errorf("--ttl must be positive")
	}
	if o.Timeout <= 0 {
		return fmt.Errorf("--timeout must be positive")
	}
	if o.Timeout > o.TTL {
		return fmt.Errorf("--timeout must be <= --ttl (timeout=%s, ttl=%s)", o.Timeout, o.TTL)
	}

	switch strings.ToLower(o.OutputFormat) {
	case "tree", "json", "yaml":
	default:
		return fmt.Errorf("--output must be one of tree|json|yaml")
	}
	return nil
}

// crdMode returns the TraceSession.spec.mode this options struct
// translates into.
func (o *Options) crdMode() juneauv1alpha1.TraceMode {
	if o.ObserveOnly {
		return juneauv1alpha1.TraceModeObserveOnly
	}
	return juneauv1alpha1.TraceModeActiveProbe
}

func (o *Options) crdProtocol() juneauv1alpha1.TraceProtocol {
	switch strings.ToLower(o.Protocol) {
	case "tcp":
		return juneauv1alpha1.TraceProtocolTCP
	case "udp":
		return juneauv1alpha1.TraceProtocolUDP
	case "icmp":
		return juneauv1alpha1.TraceProtocolICMP
	}
	return ""
}

func (o *Options) crdCapture() juneauv1alpha1.TraceCaptureConfig {
	level := juneauv1alpha1.TraceCaptureLevelDecision
	switch strings.ToLower(o.CaptureLevel) {
	case "summary":
		level = juneauv1alpha1.TraceCaptureLevelSummary
	case "verbose":
		level = juneauv1alpha1.TraceCaptureLevelVerbose
	}
	return juneauv1alpha1.TraceCaptureConfig{
		Level:             level,
		IncludePacketMeta: o.IncludeMeta,
		IncludeMapMiss:    o.IncludeMisses,
		IncludePolicy:     o.IncludePolicy,
		IncludeNAT:        o.IncludeNAT,
	}
}

func splitNamespacedName(in, defaultNs string) (ns, name string) {
	parts := strings.SplitN(in, "/", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return defaultNs, parts[0]
}

func randomTraceID() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Should never happen on a healthy host; fall back to a
		// time-based ID so the command can still proceed.
		return uint32(time.Now().UnixNano() & 0x7fffffff)
	}
	id := binary.BigEndian.Uint32(b[:])
	if id == 0 {
		id = 1 // 0 is the BPF sentinel for "no trace".
	}
	return id
}
