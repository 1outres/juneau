package topology

import (
	"context"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// ResolvePodContext walks the chain Pod → NetworkInterfaceAttachment(s)
// → NetworkInterface(s) → Subnet → Vpc → RouteTable / NetworkACL /
// SecurityGroup / ElasticIP and returns a flat snapshot suitable for
// rendering. The walk is
// best-effort: if any link is missing (Pod has no NIC yet, ACL ref
// dangles) the corresponding field is left nil and the presenter
// surfaces "(not found)" or "(none)" — the command itself does not
// fail.
func ResolvePodContext(ctx context.Context, v View, namespace, name string) (*PodContext, error) {
	out := &PodContext{Namespace: namespace, Name: name}

	pod, err := v.Pod(ctx, namespace, name)
	if err != nil {
		return nil, err
	}
	out.Pod = pod
	if pod == nil {
		return out, nil
	}

	nics, err := v.NetworkInterfacesByPod(ctx, namespace, name, string(pod.UID))
	if err != nil {
		return nil, err
	}

	out.Interfaces = make([]InterfaceContext, 0, len(nics))
	for i := range nics {
		ic, err := buildInterfaceContext(ctx, v, &nics[i])
		if err != nil {
			return nil, err
		}
		out.Interfaces = append(out.Interfaces, ic)
	}
	return out, nil
}

// ResolveNetworkInterfaceContext is the same chain as ResolvePodContext
// but rooted at a single named NetworkInterface. Used by `describe
// networkinterface`.
func ResolveNetworkInterfaceContext(ctx context.Context, v View, namespace, name string) (*InterfaceContext, error) {
	nic, err := v.NetworkInterface(ctx, namespace, name)
	if err != nil {
		return nil, err
	}
	if nic == nil {
		return &InterfaceContext{}, nil
	}
	ic, err := buildInterfaceContext(ctx, v, nic)
	if err != nil {
		return nil, err
	}
	return &ic, nil
}

// buildInterfaceContext is shared between ResolvePodContext and
// ResolveNetworkInterfaceContext.
func buildInterfaceContext(ctx context.Context, v View, nic *juneauv1alpha1.NetworkInterface) (InterfaceContext, error) {
	ic := InterfaceContext{NetworkInterface: nic}

	if nic.Spec.AttachmentRef != nil {
		attachment, err := v.NetworkInterfaceAttachment(ctx, nic.Namespace, nic.Spec.AttachmentRef.Name)
		if err != nil {
			return ic, err
		}
		if attachment != nil && attachment.UID == nic.Spec.AttachmentRef.UID {
			ic.Attachment = attachment
		}
	}

	if nic.Spec.Subnet != "" {
		subnet, err := v.Subnet(ctx, nic.Spec.Subnet)
		if err != nil {
			return ic, err
		}
		ic.Subnet = subnet

		if subnet != nil && subnet.Spec.Vpc != "" {
			vpc, err := v.Vpc(ctx, subnet.Spec.Vpc)
			if err != nil {
				return ic, err
			}
			ic.Vpc = vpc

			rt, isMain, err := resolveRouteTableForSubnet(ctx, v, subnet, vpc)
			if err != nil {
				return ic, err
			}
			ic.RouteTable = summariseRouteTable(rt, isMain)
			ic.RouteTableIsMain = isMain
		}

		if subnet != nil && subnet.Spec.NetworkACL != "" {
			acl, err := v.NetworkACL(ctx, subnet.Spec.NetworkACL)
			if err != nil {
				return ic, err
			}
			ic.NetworkACL = summariseNetworkACL(acl)
		}
	}

	// SecurityGroups: use status.effectiveSecurityGroups (what the
	// controller actually applied) so a stale spec entry never shows
	// as effective. Resolve names back to SG resources for rule
	// counts.
	for _, ref := range nic.Status.EffectiveSecurityGroups {
		sg, err := v.SecurityGroup(ctx, ref.Name)
		if err != nil {
			return ic, err
		}
		if sg == nil {
			ic.SecurityGroups = append(ic.SecurityGroups, SecurityGroupSummary{
				Name:    ref.Name,
				GroupID: ref.GroupID,
			})
			continue
		}
		ic.SecurityGroups = append(ic.SecurityGroups, summariseSecurityGroup(sg))
	}

	// ElasticIP: take the first attachment that targets this NIC. Two
	// is unusual (and would be webhook-rejected today) but if it
	// happens we surface only the first to keep the tree readable.
	attachments, err := v.ElasticIPAttachmentsForNIC(ctx, nic.Name)
	if err != nil {
		return ic, err
	}
	if len(attachments) > 0 {
		att := attachments[0]
		ic.ElasticIP = &ElasticIPSummary{
			AttachmentName: att.Name,
			ElasticIPName:  att.Spec.ElasticIPRef.Name,
			Address:        att.Status.ElasticIP,
			Phase:          att.Status.Phase,
		}
	}
	return ic, nil
}
