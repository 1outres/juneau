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

type nicOptions struct {
	Factory    factory.Factory
	PrintFlags *output.PrintFlags

	Namespace string
	Name      string
}

func newNetworkInterfaceCommand(f factory.Factory) *cobra.Command {
	o := &nicOptions{Factory: f, PrintFlags: output.NewPrintFlags()}
	cmd := &cobra.Command{
		Use:     "networkinterface NAME",
		Short:   "Show a NetworkInterface's resource chain",
		Aliases: []string{"nic", "ni", "iface"},
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

func (o *nicOptions) Validate() error {
	if o.Name == "" {
		return fmt.Errorf("network interface name is required")
	}
	if _, err := o.PrintFlags.Format(); err != nil {
		return err
	}
	return nil
}

func (o *nicOptions) Run(ctx context.Context) error {
	cl, err := o.Factory.Kube()
	if err != nil {
		return err
	}
	view := topology.NewKubeView(cl)

	nc, err := topology.ResolveNetworkInterfaceContext(ctx, view, o.Namespace, o.Name)
	if err != nil {
		return err
	}

	renderer, err := output.ResolveRenderer[*topology.InterfaceContext](
		o.PrintFlags,
		output.RendererFunc[*topology.InterfaceContext](presentNICTree),
	)
	if err != nil {
		return err
	}
	return renderer.Render(o.Factory.Streams().Out, nc)
}

func presentNICTree(w io.Writer, ic *topology.InterfaceContext) error {
	if ic.NetworkInterface == nil {
		root := output.NewNode("NetworkInterface  (not found)")
		return output.WriteTree(w, root)
	}
	root := output.NewNode(fmt.Sprintf("NetworkInterface  %s/%s  (phase: %s, address: %s)",
		ic.NetworkInterface.Namespace, ic.NetworkInterface.Name,
		displayOrDash(string(ic.NetworkInterface.Status.Phase)),
		displayOrDash(ic.NetworkInterface.Status.Address)))

	root.Childf("Pod      %s/%s  (uid: %s, iface: %s)",
		displayOrDash(ic.NetworkInterface.Namespace),
		displayOrDash(ic.NetworkInterface.Spec.PodRef.Name),
		displayOrDash(ic.NetworkInterface.Spec.PodRef.UID),
		displayOrDash(ic.NetworkInterface.Spec.PodRef.Interface))
	root.Childf("Node     %s", displayOrDash(ic.NetworkInterface.Spec.NodeName))

	if ic.Subnet != nil {
		sub := root.Childf("Subnet   %s  (cidr: %s, vni: %d)",
			ic.Subnet.Name, ic.Subnet.Spec.CIDR, ic.Subnet.Status.VNI)
		if ic.Vpc != nil {
			sub.Childf("Vpc  %s  (vpcID: %d)", ic.Vpc.Name, ic.Vpc.Status.VpcID)
		}
	}

	appendRouteTableNode(root, ic.RouteTable, ic.RouteTableIsMain)
	if ic.NetworkACL != nil {
		root.Childf("NetworkACL  %s  (aclID: %d)", ic.NetworkACL.Name, ic.NetworkACL.ACLID)
	}
	appendSecurityGroupsNode(root, ic.SecurityGroups)
	appendElasticIPNode(root, ic.ElasticIP)

	return output.WriteTree(w, root)
}
