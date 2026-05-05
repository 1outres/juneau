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

type subnetOptions struct {
	Factory    factory.Factory
	PrintFlags *output.PrintFlags

	Name string
}

func newSubnetCommand(f factory.Factory) *cobra.Command {
	o := &subnetOptions{Factory: f, PrintFlags: output.NewPrintFlags()}
	cmd := &cobra.Command{
		Use:   "subnet NAME",
		Short: "Show a Subnet's networking context",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			o.Name = args[0]
			if err := o.Validate(); err != nil {
				return err
			}
			return o.Run(c.Context())
		},
	}
	o.PrintFlags.AddFlags(cmd)
	return cmd
}

func (o *subnetOptions) Validate() error {
	if o.Name == "" {
		return fmt.Errorf("subnet name is required")
	}
	if _, err := o.PrintFlags.Format(); err != nil {
		return err
	}
	return nil
}

func (o *subnetOptions) Run(ctx context.Context) error {
	cl, err := o.Factory.Kube()
	if err != nil {
		return err
	}
	view := topology.NewKubeView(cl)

	sc, err := topology.ResolveSubnetContext(ctx, view, o.Name)
	if err != nil {
		return err
	}

	renderer, err := output.ResolveRenderer[*topology.SubnetContext](
		o.PrintFlags,
		output.RendererFunc[*topology.SubnetContext](presentSubnetTree),
	)
	if err != nil {
		return err
	}
	return renderer.Render(o.Factory.Streams().Out, sc)
}

func presentSubnetTree(w io.Writer, sc *topology.SubnetContext) error {
	if sc.Subnet == nil {
		root := output.NewNode(fmt.Sprintf("Subnet  %s  (not found)", sc.Name))
		return output.WriteTree(w, root)
	}
	root := output.NewNode(fmt.Sprintf("Subnet  %s  (cidr: %s, vni: %d)",
		sc.Subnet.Name, sc.Subnet.Spec.CIDR, sc.Subnet.Status.VNI))

	if sc.Vpc != nil {
		root.Childf("Vpc  %s  (vpcID: %d, serviceEnabled: %t, consume: %t, provider: %s, enforceSecurityGroups: %t)",
			sc.Vpc.Name, sc.Vpc.Status.VpcID,
			sc.Vpc.Spec.ServiceEnabled(),
			sc.Vpc.Spec.Service.Consumes(),
			displayOrDash(sc.Vpc.Spec.Service.ProviderSubnet()),
			sc.Vpc.Spec.EnforceSecurityGroups)
	} else if sc.Subnet.Spec.Vpc != "" {
		root.Childf("Vpc  %s  (not found)", sc.Subnet.Spec.Vpc)
	}

	tag := "main"
	if sc.RouteTable != nil && !sc.RouteTableIsMain {
		tag = "override"
	}
	if sc.RouteTable == nil {
		root.Child("RouteTable  (unresolved)")
	} else {
		rtNode := root.Childf("RouteTable  %s  (%s, %d routes)",
			sc.RouteTable.Name, tag, len(sc.RouteTable.Routes))
		for _, route := range sc.RouteTable.Routes {
			rtNode.Childf("%s  ->  %s", route.Dst, formatRouteVia(route))
		}
	}

	if sc.NetworkACL != nil {
		root.Childf("NetworkACL  %s  (aclID: %d, ingress: %d, egress: %d, rulesetVersion: %d)",
			sc.NetworkACL.Name, sc.NetworkACL.ACLID,
			sc.NetworkACL.IngressRules, sc.NetworkACL.EgressRules,
			sc.NetworkACL.RulesetVersion)
	} else if sc.Subnet.Spec.NetworkACL != "" {
		root.Childf("NetworkACL  %s  (not found)", sc.Subnet.Spec.NetworkACL)
	} else {
		root.Child("NetworkACL  (none)")
	}

	if sc.Subnet.Status.Gateway != "" {
		root.Childf("Gateway  %s  (mac: %s)",
			sc.Subnet.Status.Gateway, displayOrDash(sc.Subnet.Status.GatewayMAC))
	}
	if sc.Subnet.Status.DNS != "" {
		root.Childf("DNS      %s  (mac: %s)",
			sc.Subnet.Status.DNS, displayOrDash(sc.Subnet.Status.DNSMAC))
	}

	if len(sc.Interfaces) == 0 {
		root.Child("NetworkInterfaces  (none)")
	} else {
		nicRoot := root.Childf("NetworkInterfaces  (%d)", len(sc.Interfaces))
		for _, nic := range sc.Interfaces {
			nicRoot.Childf("%s  (pod: %s/%s, address: %s)",
				nic.Name,
				displayOrDash(nic.Namespace),
				displayOrDash(nic.Spec.PodRef.Name),
				displayOrDash(nic.Status.Address))
		}
	}

	return output.WriteTree(w, root)
}
