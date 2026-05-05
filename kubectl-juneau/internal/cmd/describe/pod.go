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

// podOptions captures everything `describe pod NAME` needs after flag
// parsing. The struct mirrors the kubectl idiom (Complete resolves
// implicit values, Validate enforces invariants, Run does the work) so
// the command is approachable to anyone who has read kubectl itself.
type podOptions struct {
	Factory    factory.Factory
	PrintFlags *output.PrintFlags

	Namespace string
	Name      string
}

func newPodCommand(f factory.Factory) *cobra.Command {
	o := &podOptions{Factory: f, PrintFlags: output.NewPrintFlags()}
	cmd := &cobra.Command{
		Use:     "pod NAME",
		Short:   "Show the Juneau networking context attached to a Pod",
		Aliases: []string{"po", "pods"},
		Args:    cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := o.Complete(args); err != nil {
				return err
			}
			if err := o.Validate(); err != nil {
				return err
			}
			return o.Run(c.Context())
		},
	}
	o.PrintFlags.AddFlags(cmd)
	return cmd
}

func (o *podOptions) Complete(args []string) error {
	o.Name = args[0]
	ns, _, err := o.Factory.Namespace()
	if err != nil {
		return err
	}
	o.Namespace = ns
	return nil
}

func (o *podOptions) Validate() error {
	if o.Name == "" {
		return fmt.Errorf("pod name is required")
	}
	if _, err := o.PrintFlags.Format(); err != nil {
		return err
	}
	return nil
}

func (o *podOptions) Run(ctx context.Context) error {
	cl, err := o.Factory.Kube()
	if err != nil {
		return err
	}
	view := topology.NewKubeView(cl)

	pc, err := topology.ResolvePodContext(ctx, view, o.Namespace, o.Name)
	if err != nil {
		return err
	}

	renderer, err := output.ResolveRenderer[*topology.PodContext](
		o.PrintFlags,
		output.RendererFunc[*topology.PodContext](presentPodTree),
	)
	if err != nil {
		return err
	}
	return renderer.Render(o.Factory.Streams().Out, pc)
}

// presentPodTree renders a PodContext into the tree view. Side-effect
// free: given the same context, the same bytes — golden tests trivial.
func presentPodTree(w io.Writer, pc *topology.PodContext) error {
	root := output.NewNode(podHeader(pc))

	if pc.Pod == nil {
		root.Child("(Pod not found in cluster)")
		return output.WriteTree(w, root)
	}
	if len(pc.Interfaces) == 0 {
		root.Child("(no NetworkInterface bound — Pod may not be admitted by Juneau yet)")
		return output.WriteTree(w, root)
	}
	for i := range pc.Interfaces {
		appendInterfaceNode(root, &pc.Interfaces[i])
	}
	return output.WriteTree(w, root)
}

func podHeader(pc *topology.PodContext) string {
	if pc.Pod == nil {
		return fmt.Sprintf("Pod  %s/%s", pc.Namespace, pc.Name)
	}
	if pc.Pod.Spec.NodeName != "" {
		return fmt.Sprintf("Pod  %s/%s  (Node: %s, podIP: %s)",
			pc.Pod.Namespace, pc.Pod.Name, pc.Pod.Spec.NodeName,
			displayOrDash(pc.Pod.Status.PodIP))
	}
	return fmt.Sprintf("Pod  %s/%s  (podIP: %s)",
		pc.Pod.Namespace, pc.Pod.Name, displayOrDash(pc.Pod.Status.PodIP))
}

// appendInterfaceNode is shared between describe pod and describe nic
// so the rendering of a single NetworkInterface stays consistent.
func appendInterfaceNode(parent *output.Node, ic *topology.InterfaceContext) {
	header := fmt.Sprintf("NetworkInterface  %s", ic.NetworkInterface.Name)
	header += fmt.Sprintf("  (phase: %s, address: %s)",
		displayOrDash(string(ic.NetworkInterface.Status.Phase)),
		displayOrDash(ic.NetworkInterface.Status.Address))
	nicNode := parent.Child(header)

	if ic.Subnet != nil {
		subnetNode := nicNode.Childf("Subnet  %s  (cidr: %s, vni: %d)",
			ic.Subnet.Name, ic.Subnet.Spec.CIDR, ic.Subnet.Status.VNI)
		if ic.Vpc != nil {
			subnetNode.Childf("Vpc  %s  (vpcID: %d, enableService: %t, enforceSecurityGroups: %t)",
				ic.Vpc.Name, ic.Vpc.Status.VpcID,
				ic.Vpc.Spec.EnableService, ic.Vpc.Spec.EnforceSecurityGroups)
		} else if ic.Subnet.Spec.Vpc != "" {
			subnetNode.Childf("Vpc  %s  (not found)", ic.Subnet.Spec.Vpc)
		}
		appendRouteTableNode(subnetNode, ic.RouteTable, ic.RouteTableIsMain)
		appendInterfaceACLNode(subnetNode, ic)
	} else if ic.NetworkInterface.Spec.Subnet != "" {
		nicNode.Childf("Subnet  %s  (not found)", ic.NetworkInterface.Spec.Subnet)
	}

	appendSecurityGroupsNode(nicNode, ic.SecurityGroups)
	appendElasticIPNode(nicNode, ic.ElasticIP)
}

func appendRouteTableNode(parent *output.Node, rt *topology.RouteTableSummary, isMain bool) {
	if rt == nil {
		parent.Child("RouteTable  (unresolved)")
		return
	}
	tag := "main"
	if !isMain {
		tag = "override"
	}
	rtNode := parent.Childf("RouteTable  %s  (%s, %d routes)", rt.Name, tag, len(rt.Routes))
	for _, route := range rt.Routes {
		rtNode.Childf("%s  ->  %s", route.Dst, formatRouteVia(route))
	}
}

func appendInterfaceACLNode(parent *output.Node, ic *topology.InterfaceContext) {
	if ic.NetworkACL != nil {
		parent.Childf("NetworkACL  %s  (aclID: %d, ingress: %d, egress: %d, rulesetVersion: %d)",
			ic.NetworkACL.Name, ic.NetworkACL.ACLID,
			ic.NetworkACL.IngressRules, ic.NetworkACL.EgressRules,
			ic.NetworkACL.RulesetVersion)
		return
	}
	if ic.Subnet != nil && ic.Subnet.Spec.NetworkACL != "" {
		parent.Childf("NetworkACL  %s  (not found)", ic.Subnet.Spec.NetworkACL)
		return
	}
	parent.Child("NetworkACL  (none)")
}

func appendSecurityGroupsNode(parent *output.Node, sgs []topology.SecurityGroupSummary) {
	if len(sgs) == 0 {
		parent.Child("SecurityGroups  (none)")
		return
	}
	sgRoot := parent.Childf("SecurityGroups  (%d)", len(sgs))
	for _, sg := range sgs {
		egress := "default-allow"
		if sg.HasEgressRules {
			egress = fmt.Sprintf("%d rule(s)", sg.EgressRules)
		}
		sgRoot.Childf("%s  (groupID: %d, ingress: %d, egress: %s)",
			sg.Name, sg.GroupID, sg.IngressRules, egress)
	}
}

func appendElasticIPNode(parent *output.Node, eip *topology.ElasticIPSummary) {
	if eip == nil {
		parent.Child("ElasticIP  (none)")
		return
	}
	parent.Childf("ElasticIP  %s  (address: %s, phase: %s)",
		eip.AttachmentName, displayOrDash(eip.Address), displayOrDash(string(eip.Phase)))
}
