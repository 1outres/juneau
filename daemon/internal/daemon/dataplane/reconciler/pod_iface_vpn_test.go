package reconciler

import (
	"context"
	"testing"

	juneau "github.com/1outres/juneau/controller/api/v1alpha1"
	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestVPNSourceExceptionOnlyForReadyGatewayNIC(t *testing.T) {
	endpoint := newPodIfaceEndpoint("10.16.0.5/24")
	endpoint.Spec.MACAddress = "02:00:00:00:00:05"
	subnet := newPodIfaceSubnet()
	subnet.Spec.Vpc = "tenant"
	subnet.Status.GatewayMAC = "02:00:00:00:00:01"
	subnet.Status.Conditions = []metav1.Condition{{Type: juneau.SubnetStatusReady, Status: metav1.ConditionTrue}}
	vpn := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "branch", UID: "vpn-uid", Generation: 1}, Spec: juneau.VPNSpec{Vpc: "tenant", Subnet: "subnet-a"}, Status: juneau.VPNStatus{ObservedGeneration: 1, Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, ObservedGeneration: 1}}}}
	endpoint.Name = vpnGatewayPodName(vpn) + ".eth0"
	endpoint.Spec.PodRef = &juneau.NetworkEndpointPodReference{UID: "pod-uid", Name: vpnGatewayPodName(vpn), Interface: "eth0"}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: vpnGatewayPodName(vpn), Namespace: "default", UID: "pod-uid", OwnerReferences: []metav1.OwnerReference{{Kind: "VPN", Name: vpn.Name, UID: vpn.UID}}}, Spec: corev1.PodSpec{NodeName: "node-a"}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
	nic := &juneau.NetworkInterface{ObjectMeta: metav1.ObjectMeta{Name: pod.Name + ".eth0", Namespace: "default", Generation: 1}, Spec: juneau.NetworkInterfaceSpec{NodeName: "node-a", Subnet: subnet.Name, PodRef: juneau.NetworkInterfacePodReference{UID: string(pod.UID), Name: pod.Name, Interface: "eth0"}}, Status: juneau.NetworkInterfaceStatus{Phase: juneau.NetworkInterfacePhaseReady, ObservedGeneration: 1, Address: endpoint.Spec.Address}}
	r, maps := newPodIfaceFixture(t, endpoint, subnet, vpn, pod, nic)
	if err := r.Reconcile(context.Background(), "default/"+endpoint.Name); err != nil {
		t.Fatal(err)
	}
	key := bpf.PodEgressVpnGatewayKey{Ifindex: 7}
	if got := maps.vpnGateway.entries[key]; got != (bpf.PodEgressVpnIdentity{Bytes: vpnIdentity(vpn.UID)}) {
		t.Fatalf("gateway identity=%v", got)
	}
	vpn.Status.Conditions = nil
	if err := r.client.Update(context.Background(), vpn); err != nil {
		t.Fatal(err)
	}
	if err := r.Reconcile(context.Background(), "default/"+endpoint.Name); err != nil {
		t.Fatal(err)
	}
	if _, ok := maps.vpnGateway.entries[key]; ok {
		t.Fatal("unready VPN source exception remains")
	}
	if err := r.client.Delete(context.Background(), endpoint); err != nil {
		t.Fatal(err)
	}
	if err := r.Reconcile(context.Background(), "default/"+endpoint.Name); err != nil {
		t.Fatal(err)
	}
	if _, ok := maps.vpnGateway.entries[key]; ok {
		t.Fatal("deleted endpoint retained source exception")
	}
}
