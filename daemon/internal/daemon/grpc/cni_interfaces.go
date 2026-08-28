package grpc

import (
	"fmt"
	"sort"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
)

// orderPodInterfaces returns the NICs of one pod with the primary first
// and the rest in name order. The order decides the interface indexes of
// the CNI result, so it has to be the same on every retry.
func orderPodInterfaces(items []juneauv1alpha1.NetworkInterface, primaryIfname string) []*juneauv1alpha1.NetworkInterface {
	out := make([]*juneauv1alpha1.NetworkInterface, 0, len(items))
	for i := range items {
		out = append(out, &items[i])
	}
	sort.SliceStable(out, func(i, j int) bool {
		left, right := out[i].Spec.PodRef.Interface, out[j].Spec.PodRef.Interface
		if (left == primaryIfname) != (right == primaryIfname) {
			return left == primaryIfname
		}
		return left < right
	})
	return out
}

// checkPodInterfacesAllocated reports the first NIC the controller has
// not finished with. A pod gets all of its NICs at once, so a
// half-allocated pod waits instead of coming up with fewer NICs than it
// asked for, which would leave a later DEL guessing what to take down.
//
// Being allocated is not the same as having an address. An L2Network
// without a CIDR hands out none, and a NIC on one is allocated the
// moment the controller has said so. The one NIC that really does need
// an address is the pod's first, and checkPrimaryPodInterface is what
// says so.
func checkPodInterfacesAllocated(ifaces []*juneauv1alpha1.NetworkInterface) error {
	for _, nwiface := range ifaces {
		ifname := nwiface.Spec.PodRef.Interface
		if !meta.IsStatusConditionTrue(nwiface.Status.Conditions, juneauv1alpha1.NetworkInterfaceStatusAllocated) {
			return fmt.Errorf("NetworkInterface %s of %q is not allocated yet", nwiface.Name, ifname)
		}
	}
	return nil
}

// filterPodInterfaces keeps the NICs the pod currently asks for. The pod
// is what says which NICs it wants; a NetworkInterface left over from an
// earlier version of its annotation is on its way out and must neither be
// built nor hold the sandbox back.
func filterPodInterfaces(ifaces []*juneauv1alpha1.NetworkInterface, wanted []juneauv1alpha1.PodNetworkAttachment) []*juneauv1alpha1.NetworkInterface {
	asked := make(map[string]struct{}, len(wanted))
	for _, attachment := range wanted {
		asked[attachment.Interface] = struct{}{}
	}
	out := make([]*juneauv1alpha1.NetworkInterface, 0, len(ifaces))
	for _, nwiface := range ifaces {
		if _, ok := asked[nwiface.Spec.PodRef.Interface]; ok {
			out = append(out, nwiface)
		}
	}
	return out
}

// checkPodInterfacesComplete reports the first NIC the pod asks for and
// the controller has not written a NetworkInterface for yet. A CNI ADD
// builds all the NICs of a pod in one go, so it has to see all of them
// before it starts: a sandbox that came up with fewer NICs than it asked
// for never gets a second ADD to finish the job.
func checkPodInterfacesComplete(ifaces []*juneauv1alpha1.NetworkInterface, wanted []juneauv1alpha1.PodNetworkAttachment) error {
	found := make(map[string]struct{}, len(ifaces))
	for _, nwiface := range ifaces {
		found[nwiface.Spec.PodRef.Interface] = struct{}{}
	}
	for _, attachment := range wanted {
		if _, ok := found[attachment.Interface]; !ok {
			return fmt.Errorf("the pod asks for a NIC %q that has no NetworkInterface yet", attachment.Interface)
		}
	}
	return nil
}

// checkPrimaryPodInterface reports a pod that cannot be handed to the
// container runtime. The runtime reads the pod address off the CNI result
// interface named after the primary NIC and fails the sandbox when that
// interface is missing or carries no address, so saying so here names the
// real cause instead of leaving it to the runtime.
func checkPrimaryPodInterface(ifaces []*juneauv1alpha1.NetworkInterface, primaryIfname string) error {
	for _, nwiface := range ifaces {
		if nwiface.Spec.PodRef.Interface != primaryIfname {
			continue
		}
		if nwiface.Status.Address == "" {
			return fmt.Errorf("the primary NIC %q of the pod has no address", primaryIfname)
		}
		return nil
	}
	return fmt.Errorf("the pod has no NetworkInterface for its primary NIC %q", primaryIfname)
}

// podNICsToRelease lists the interface names whose NetworkEndpoint one
// CNI DEL has to release, primary first.
//
// Both sources are needed. The endpoints alone would miss a NIC the
// daemon cache has not seen yet, which happens when a sandbox is torn
// down right after it came up. The pod alone would miss a NIC the user
// has since dropped from the annotation. Releasing a NIC that has no
// endpoint costs one lookup and finds nothing.
func podNICsToRelease(endpoints []juneauv1alpha1.NetworkEndpoint, wanted []juneauv1alpha1.PodNetworkAttachment, podName, podUID, primaryIfname string) []string {
	seen := map[string]struct{}{primaryIfname: {}}
	extra := make([]string, 0, len(endpoints)+len(wanted))

	add := func(ifname string) {
		if ifname == "" {
			return
		}
		if _, known := seen[ifname]; known {
			return
		}
		seen[ifname] = struct{}{}
		extra = append(extra, ifname)
	}

	for i := range endpoints {
		ref := endpoints[i].Spec.PodRef
		if ref == nil || ref.Name != podName || ref.UID != podUID {
			continue
		}
		add(ref.Interface)
	}
	for _, attachment := range wanted {
		add(attachment.Interface)
	}

	sort.Strings(extra)
	return append([]string{primaryIfname}, extra...)
}
