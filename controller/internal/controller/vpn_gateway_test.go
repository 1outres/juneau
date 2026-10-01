package controller

import (
	"strings"
	"testing"

	juneau "github.com/1outres/juneau/controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestVPNGatewayPodUsesAllocatedEndpointAndPSKMount(t *testing.T) {
	vpn := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: "site", Namespace: "tenant", UID: "uid-1"}, Spec: juneau.VPNSpec{Subnet: "inside", LocalASN: 64512, RemoteASN: 64513, PeerIKEID: "router", PSKSecretRef: juneau.VPNSecretRef{Name: "psk", Key: "password"}}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "psk", ResourceVersion: "7"}, Data: map[string][]byte{"password": []byte("must-not-leak")}}
	pod, err := vpnGatewayPod(vpn, secret, "gateway:1", "169.254.51.1", "169.254.51.2", "public-ip", "203.0.113.20", []string{"192.0.2.0/24"}, []string{"10.0.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	container := pod.Spec.Containers[0]
	if pod.Annotations[juneau.PodAnnotationNetworks] == "" || !strings.Contains(pod.Annotations[juneau.PodAnnotationNetworks], `"elasticIP":"public-ip"`) {
		t.Fatal("missing direct public NIC")
	}
	if container.ReadinessProbe == nil || container.ReadinessProbe.Exec == nil {
		t.Fatal("gateway has no health check")
	}
	values := make(map[string]string)
	for _, env := range container.Env {
		values[env.Name] = env.Value
	}
	if values["PUBLIC_IP"] != "203.0.113.20" || values["VPN_REMOTE_ROUTES"] != `["192.0.2.0/24"]` || values["VPN_ADVERTISED_ROUTES"] != `["10.0.0.0/24"]` || values["VPN_PSK_FILE"] != "/etc/juneau/vpn/psk" {
		t.Fatalf("wrong gateway config: %v", values)
	}
	if pod.Spec.Volumes[0].Secret.SecretName != "psk" || pod.Spec.Volumes[0].Secret.Items[0].Key != "password" {
		t.Fatal("wrong PSK mount")
	}
	if strings.Contains(pod.String(), "must-not-leak") {
		t.Fatal("PSK leaked into Pod spec")
	}
	defaulted := pod.DeepCopy()
	defaulted.Spec.DNSPolicy = corev1.DNSClusterFirst
	defaulted.Spec.Containers[0].TerminationMessagePath = "/dev/termination-log"
	if !vpnPodMatches(defaulted, pod) {
		t.Fatal("API defaults should not trigger endless Pod replacement")
	}
	changed := pod.DeepCopy()
	changed.Annotations[vpnSecretVersion] = "8"
	if vpnPodMatches(changed, pod) {
		t.Fatal("Secret change must replace Pod")
	}
	changed = pod.DeepCopy()
	for i := range changed.Spec.Containers[0].Env {
		if changed.Spec.Containers[0].Env[i].Name == "VPN_REMOTE_ROUTES" {
			changed.Spec.Containers[0].Env[i].Value = `[]`
		}
	}
	if vpnPodMatches(changed, pod) {
		t.Fatal("RouteTable change must replace Pod")
	}
}

func TestVPNNamesFitKubernetesLimit(t *testing.T) {
	vpn := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: strings.Repeat("a", 63), UID: types.UID("some-uid")}}
	if len(vpnPodName(vpn)) > 63 || len(vpnEIPName(vpn)) > 63 {
		t.Fatal("resource names exceed DNS label limit")
	}
}
