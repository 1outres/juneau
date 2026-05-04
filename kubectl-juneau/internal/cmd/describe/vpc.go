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

type vpcOptions struct {
	Factory    factory.Factory
	PrintFlags *output.PrintFlags

	Name string
}

func newVpcCommand(f factory.Factory) *cobra.Command {
	o := &vpcOptions{Factory: f, PrintFlags: output.NewPrintFlags()}
	cmd := &cobra.Command{
		Use:   "vpc NAME",
		Short: "Show the resources that belong to a Vpc",
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

func (o *vpcOptions) Validate() error {
	if o.Name == "" {
		return fmt.Errorf("vpc name is required")
	}
	if _, err := o.PrintFlags.Format(); err != nil {
		return err
	}
	return nil
}

func (o *vpcOptions) Run(ctx context.Context) error {
	cl, err := o.Factory.Kube()
	if err != nil {
		return err
	}
	view := topology.NewKubeView(cl)

	vc, err := topology.ResolveVpcContext(ctx, view, o.Name)
	if err != nil {
		return err
	}

	renderer, err := output.ResolveRenderer[*topology.VpcContext](
		o.PrintFlags,
		output.RendererFunc[*topology.VpcContext](presentVpcTree),
	)
	if err != nil {
		return err
	}
	return renderer.Render(o.Factory.Streams().Out, vc)
}

func presentVpcTree(w io.Writer, vc *topology.VpcContext) error {
	if vc.Vpc == nil {
		root := output.NewNode(fmt.Sprintf("Vpc  %s  (not found)", vc.Name))
		return output.WriteTree(w, root)
	}
	root := output.NewNode(fmt.Sprintf("Vpc  %s  (vpcID: %d)", vc.Vpc.Name, vc.Vpc.Status.VpcID))

	spec := root.Child("Spec")
	spec.Childf("enableService:         %t", vc.Vpc.Spec.EnableService)
	spec.Childf("enforceSecurityGroups: %t", vc.Vpc.Spec.EnforceSecurityGroups)

	if len(vc.Subnets) == 0 {
		root.Child("Subnets  (none)")
	} else {
		sn := root.Childf("Subnets  (%d)", len(vc.Subnets))
		for _, s := range vc.Subnets {
			sn.Childf("%s  (cidr: %s, vni: %d)", s.Name, s.Spec.CIDR, s.Status.VNI)
		}
	}

	if len(vc.RouteTables) == 0 {
		root.Child("RouteTables  (none)")
	} else {
		rn := root.Childf("RouteTables  (%d)", len(vc.RouteTables))
		for _, rt := range vc.RouteTables {
			tag := ""
			if rt.IsMain {
				tag = ", main"
			}
			rn.Childf("%s  (%d routes%s)", rt.Name, len(rt.Routes), tag)
		}
	}

	if len(vc.SecurityGroups) == 0 {
		root.Child("SecurityGroups  (none)")
	} else {
		sgn := root.Childf("SecurityGroups  (%d)", len(vc.SecurityGroups))
		for _, sg := range vc.SecurityGroups {
			sgn.Childf("%s  (groupID: %d)", sg.Name, sg.GroupID)
		}
	}

	if len(vc.NetworkACLs) == 0 {
		root.Child("NetworkACLs  (none)")
	} else {
		acln := root.Childf("NetworkACLs  (%d)", len(vc.NetworkACLs))
		for _, acl := range vc.NetworkACLs {
			acln.Childf("%s  (aclID: %d, ingress: %d, egress: %d)",
				acl.Name, acl.ACLID, acl.IngressRules, acl.EgressRules)
		}
	}

	if len(vc.NATGateways) == 0 {
		root.Child("NATGateways  (none)")
	} else {
		ngn := root.Childf("NATGateways  (%d)", len(vc.NATGateways))
		for _, ng := range vc.NATGateways {
			ngn.Childf("%s  ->  %s  (gatewayID: %d)",
				ng.Name, ng.ExternalNetwork, ng.GatewayID)
		}
	}

	return output.WriteTree(w, root)
}
