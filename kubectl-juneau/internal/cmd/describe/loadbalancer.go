package describe

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/kubectl-juneau/internal/factory"
	"github.com/1outres/juneau/kubectl-juneau/internal/output"
	"github.com/1outres/juneau/kubectl-juneau/internal/topology"
)

type loadBalancerOptions struct {
	Factory    factory.Factory
	PrintFlags *output.PrintFlags

	Namespace string
	Name      string
}

func newLoadBalancerCommand(f factory.Factory) *cobra.Command {
	o := &loadBalancerOptions{Factory: f, PrintFlags: output.NewPrintFlags()}
	cmd := &cobra.Command{
		Use:     "loadbalancer NAME",
		Short:   "Show a Juneau-managed Service LoadBalancer's VIP, advertising nodes, and backend reachability",
		Aliases: []string{"slb", "serviceloadbalancer"},
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

func (o *loadBalancerOptions) Validate() error {
	if o.Name == "" {
		return fmt.Errorf("loadbalancer name is required")
	}
	if _, err := o.PrintFlags.Format(); err != nil {
		return err
	}
	return nil
}

func (o *loadBalancerOptions) Run(ctx context.Context) error {
	cl, err := o.Factory.Kube()
	if err != nil {
		return err
	}
	view := topology.NewKubeView(cl)

	lbc, err := topology.ResolveLoadBalancerContext(ctx, view, o.Namespace, o.Name)
	if err != nil {
		return err
	}

	renderer, err := output.ResolveRenderer[*topology.LoadBalancerContext](
		o.PrintFlags,
		output.RendererFunc[*topology.LoadBalancerContext](presentLoadBalancerTree),
	)
	if err != nil {
		return err
	}
	return renderer.Render(o.Factory.Streams().Out, lbc)
}

func presentLoadBalancerTree(w io.Writer, lbc *topology.LoadBalancerContext) error {
	if lbc.SLB == nil {
		root := output.NewNode(fmt.Sprintf("ServiceLoadBalancer  %s/%s  (not found)", lbc.Namespace, lbc.Name))
		if lbc.Service != nil {
			root.Childf("parent Service exists but no SLB has been reconciled — check loadBalancerClass=%q", juneauv1alpha1.LoadBalancerClass)
		}
		return output.WriteTree(w, root)
	}

	slb := lbc.SLB
	root := output.NewNode(fmt.Sprintf("ServiceLoadBalancer  %s/%s  (vip: %s, phase: %s)",
		slb.Namespace, slb.Name,
		displayOrDash(slb.Status.VIP),
		displayOrDash(string(slb.Status.Phase))))

	if lbc.Service == nil {
		root.Childf("parent Service %s/%s  (not found)", slb.Namespace, slb.Spec.ServiceRef.Name)
	} else {
		root.Childf("parent Service  %s/%s  (type=%s, externalTrafficPolicy=%s)",
			lbc.Service.Namespace, lbc.Service.Name,
			lbc.Service.Spec.Type, lbc.Service.Spec.ExternalTrafficPolicy)
	}

	enLabel := fmt.Sprintf("ExternalNetwork  %s", displayOrDash(slb.Spec.ExternalNetwork))
	if lbc.ExternalNetwork != nil {
		enLabel += fmt.Sprintf("  type=%s  pools=%s",
			lbc.ExternalNetwork.Spec.Type,
			strings.Join(lbc.ExternalNetwork.Spec.AddressPools, ","))
	} else if slb.Spec.ExternalNetwork != "" {
		enLabel += "  (not found)"
	}
	root.Child(enLabel)

	if slb.Spec.RequestedIP != "" {
		root.Childf("RequestedIP  %s", slb.Spec.RequestedIP)
	}
	if slb.Status.AddressPool != "" {
		root.Childf("AllocatedFrom  AddressPool/%s", slb.Status.AddressPool)
	}

	if len(slb.Status.Ports) == 0 {
		root.Child("Ports  (none)")
	} else {
		ports := root.Child("Ports")
		for _, p := range slb.Status.Ports {
			ports.Childf("%s/%d  ->  %d", string(p.Protocol), p.Port, p.TargetPort)
		}
	}

	if len(slb.Status.AdvertisingNodes) == 0 {
		root.Child("AdvertisingNodes  (none — VIP is not currently advertised)")
	} else {
		ads := root.Childf("AdvertisingNodes  (%d)", len(slb.Status.AdvertisingNodes))
		for _, n := range slb.Status.AdvertisingNodes {
			ads.Child(n)
		}
	}

	root.Childf("Backends  totalReady=%d  localReadyNodes=%d",
		slb.Status.BackendSummary.TotalReady,
		slb.Status.BackendSummary.LocalReadyNodes)

	if len(slb.Status.Conditions) > 0 {
		conds := root.Child("Conditions")
		for _, c := range slb.Status.Conditions {
			conds.Childf("%s=%s  reason=%s  age=%s",
				c.Type, c.Status, displayOrDash(c.Reason), conditionAge(c))
		}
	}

	return output.WriteTree(w, root)
}

func conditionAge(c metav1.Condition) string {
	if c.LastTransitionTime.IsZero() {
		return "-"
	}
	return c.LastTransitionTime.Format("2006-01-02T15:04:05Z07:00")
}
