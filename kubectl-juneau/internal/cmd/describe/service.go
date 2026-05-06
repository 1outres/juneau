package describe

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/1outres/juneau/kubectl-juneau/internal/factory"
	"github.com/1outres/juneau/kubectl-juneau/internal/output"
	"github.com/1outres/juneau/kubectl-juneau/internal/topology"
)

type serviceOptions struct {
	Factory    factory.Factory
	PrintFlags *output.PrintFlags

	Namespace string
	Name      string
}

func newServiceCommand(f factory.Factory) *cobra.Command {
	o := &serviceOptions{Factory: f, PrintFlags: output.NewPrintFlags()}
	cmd := &cobra.Command{
		Use:     "service NAME",
		Short:   "Show a Service's Vpc binding and backend reachability",
		Aliases: []string{"svc"},
		Args:    cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			o.Name = args[0]
			ns, _, err := o.Factory.Namespace()
			if err != nil {
				return err
			}
			o.Namespace = ns
			if err := o.Validate(); err != nil {
				return err
			}
			return o.Run(c.Context())
		},
	}
	o.PrintFlags.AddFlags(cmd)
	return cmd
}

func (o *serviceOptions) Validate() error {
	if o.Name == "" {
		return fmt.Errorf("service name is required")
	}
	if _, err := o.PrintFlags.Format(); err != nil {
		return err
	}
	return nil
}

func (o *serviceOptions) Run(ctx context.Context) error {
	cl, err := o.Factory.Kube()
	if err != nil {
		return err
	}
	view := topology.NewKubeView(cl)

	sc, err := topology.ResolveServiceContext(ctx, view, o.Namespace, o.Name)
	if err != nil {
		return err
	}

	renderer, err := output.ResolveRenderer[*topology.ServiceContext](
		o.PrintFlags,
		output.RendererFunc[*topology.ServiceContext](presentServiceTree),
	)
	if err != nil {
		return err
	}
	return renderer.Render(o.Factory.Streams().Out, sc)
}

func presentServiceTree(w io.Writer, sc *topology.ServiceContext) error {
	if sc.Service == nil {
		root := output.NewNode(fmt.Sprintf("Service  %s/%s  (not found)", sc.Namespace, sc.Name))
		return output.WriteTree(w, root)
	}

	root := output.NewNode(fmt.Sprintf("Service  %s/%s  (clusterIP: %s)",
		sc.Service.Namespace, sc.Service.Name, displayOrDash(sc.Service.Spec.ClusterIP)))

	vpcLabel := fmt.Sprintf("Vpc  %s  (from annotation)", sc.VpcName)
	if sc.VpcName == "" || sc.VpcName == "default" {
		vpcLabel = "Vpc  default  (default Vpc)"
	}
	if sc.Vpc != nil {
		vpcLabel += fmt.Sprintf("  serviceEnabled: %t  consume: %t  provider: %s",
			sc.Vpc.Spec.ServiceEnabled(),
			sc.Vpc.Spec.Service.Consumes(),
			displayOrDash(sc.Vpc.Spec.Service.ProviderSubnet()))
	} else if sc.VpcName != "" {
		vpcLabel += "  (not found)"
	}
	root.Child(vpcLabel)

	root.Childf("Shared  %t", sc.Shared)

	if len(sc.Service.Spec.Ports) == 0 {
		root.Child("Ports  (none)")
	} else {
		ports := root.Child("Ports")
		for _, p := range sc.Service.Spec.Ports {
			ports.Childf("%s/%d  ->  %s", string(p.Protocol), p.Port, p.TargetPort.String())
		}
	}

	if len(sc.Backends) == 0 {
		root.Child("Backends  (none)")
	} else {
		bk := root.Childf("Backends  (%d)", len(sc.Backends))
		for _, b := range sc.Backends {
			mark := "ok"
			if !b.SameVpc {
				mark = "VPC mismatch"
			}
			bk.Childf("%s  node=%s  pod=%s/%s  vpc=%s  [%s]",
				b.Address,
				displayOrDash(b.NodeName),
				displayOrDash(b.PodNamespace),
				displayOrDash(b.PodName),
				displayOrDash(b.VpcName),
				mark)
		}
	}

	return output.WriteTree(w, root)
}
