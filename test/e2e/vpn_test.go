package e2e

import (
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Juneau site-to-site VPN with NATed initiators", Ordered, Serial, func() {
	const peerVpc = "e2e-vpn-peer-vpc"
	const peerSubnet = "e2e-vpn-peer-subnet"
	const peerCIDR = "10.215.11.0/24"
	const peering = "e2e-vpn-peering"
	var fix *vpnFixture
	var first *vpnSite
	var acl *policyFixture
	var peeringCreated bool

	BeforeAll(func() {
		fix = newVPNFixture()
		fix.Start()
		first = fix.AddSite("branch-one", "198.18.11.10", "198.18.11.0/24")
		fix.RouteSites()
		fix.Connect(first)
		first.StartServer()
		Expect(applyManifest(podManifest(fix.namespace, "server", workerNodes[1], fix.subnet, true))).To(Succeed())
		Expect(applyManifest(podManifest(fix.namespace, "client", workerNodes[0], fix.subnet, false))).To(Succeed())
		waitPodsReady(fix.namespace, "server", "client")
	})

	AfterEach(func() {
		if peeringCreated {
			clearMainRouteTableRoutes(peerVpc)
			clearMainRouteTableRoutes(fix.vpc)
			runBestEffort(repoRoot, "kubectl", "delete", "vpcpeering", peering, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "subnet", peerSubnet, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "vpc", peerVpc, "--ignore-not-found=true")
			peeringCreated = false
		}
		if acl != nil {
			runBestEffort(repoRoot, "kubectl", "patch", "subnet", fix.subnet, "--type=merge", "-p", `{"spec":{"networkACL":""}}`)
			runBestEffort(repoRoot, "kubectl", "delete", "networkacl", acl.ACLName("ingress"), "--ignore-not-found=true", "--wait=false")
			acl = nil
		}
	})

	AfterAll(func() { fix.Cleanup() })

	It("negotiates NAT-T, learns only Vpc routes over BGP, and sends un-NATed IPv4 in both directions", func() {
		By("checking that only the NAT container has a kind-facing interface")
		out, err := dockerOutput("inspect", "-f", `{{json .NetworkSettings.Networks}}`, first.peer)
		Expect(err).NotTo(HaveOccurred())
		Expect(out).NotTo(ContainSubstring(`"kind":`))

		By("checking the ESP SA uses UDP encapsulation")
		Eventually(func(g Gomega) {
			_, err := first.Exec("sh", "-ec", "ip xfrm state | grep -q 'encap type espinudp'")
			g.Expect(err).NotTo(HaveOccurred())
		}).Should(Succeed())

		By("checking BGP does not import a prefix the site advertised")
		out, err = kubectlJSONPath(repoRoot, `{.status.routes[?(@.dst=="198.18.99.0/24")].dst}`, "get", "routetable", waitVpcMainRouteTable(fix.vpc))
		Expect(err).NotTo(HaveOccurred())
		Expect(out).To(BeEmpty())

		By("delivering from the site's source IP to a Vpc Pod")
		serverIP := mustPodIP(fix.namespace, "server")
		Eventually(func(g Gomega) {
			body, err := first.Curl(serverIP)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(strings.ToLower(body)).To(ContainSubstring("welcome to nginx"))
			logs, err := kubectlOutput(repoRoot, "logs", "-n", fix.namespace, "server")
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(logs).To(ContainSubstring(first.onPremIP + " - -"))
		}).Should(Succeed())

		By("delivering from a Vpc Pod to the site and preserving the Pod source IP")
		assertVPNPodToSite(fix.namespace, "client", first)
	})

	It("forwards GRE with the original site address across the tunnel", func() {
		Expect(applyManifest(policyPodManifest(fix.namespace, "gre-sink", workerNodes[1], fix.subnet, nil, greSinkContainer()))).To(Succeed())
		DeferCleanup(func() {
			runBestEffort(repoRoot, "kubectl", "delete", "pod", "gre-sink", "-n", fix.namespace, "--ignore-not-found=true")
		})
		waitPodsReady(fix.namespace, "gre-sink")
		waitProbeSinkReady(fix.namespace, "gre-sink")
		sinkIP := mustPodIP(fix.namespace, "gre-sink")
		const sendGRE = `import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_GRE)
s.bind((sys.argv[1], 0))
for _ in range(3): s.sendto(b"\x00\x00\x08\x00", (sys.argv[2], 0))`
		Eventually(func(g Gomega) {
			_, err := first.Exec("python3", "-c", sendGRE, first.onPremIP, sinkIP)
			g.Expect(err).NotTo(HaveOccurred())
			capture, err := probeSinkLog(fix.namespace, "gre-sink")
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(capture).To(ContainSubstring(captureFrom(first.onPremIP)))
		}).Should(Succeed())
	})

	It("updates an ACL allow-deny-allow without changing the VPN route or gateway Pod", func() {
		acl = &policyFixture{base: "vpn", vpcName: fix.vpc, serverSubnet: fix.subnet}
		acl.CreateACL("ingress", vpnACLRule("allow", first.onPremCIDR, first.siteTunnelIP, fix.natPublicIP))
		acl.AttachACL(fix.subnet, "ingress")
		podName, uid := first.GatewayPod(fix.namespace)
		serverIP := mustPodIP(fix.namespace, "server")
		assertVPNHTTPAllowed(first, serverIP)
		Expect(applyManifest(policyPodManifest(fix.namespace, "stream-sink", workerNodes[1], fix.subnet, nil,
			streamSinkContainer(policyStreamPort, policyStreamSink)))).To(Succeed())
		DeferCleanup(func() {
			runBestEffort(repoRoot, "kubectl", "delete", "pod", "stream-sink", "-n", fix.namespace, "--ignore-not-found=true")
		})
		waitPodsReady(fix.namespace, "stream-sink")
		const streamSource = `import socket, sys, time
s = socket.socket()
s.bind((sys.argv[1], 0))
s.connect((sys.argv[2], 9000))
while True:
 s.sendall(b"vpn-stream\n")
 time.sleep(1)`
		_, err := dockerOutput("exec", "-d", first.peer, "python3", "-c", streamSource,
			first.onPremIP, mustPodIP(fix.namespace, "stream-sink"))
		Expect(err).NotTo(HaveOccurred())
		waitStreamGrows(fix.namespace, "stream-sink", policyStreamSink)

		acl.ReplaceACLRules("ingress", vpnACLRule("deny", first.onPremCIDR, first.siteTunnelIP, fix.natPublicIP))
		settled := waitStreamStops(fix.namespace, "stream-sink", policyStreamSink)
		Consistently(func(g Gomega) {
			g.Expect(streamBytes(g, fix.namespace, "stream-sink", policyStreamSink)).To(Equal(settled))
		}, policyStreamQuiet, policyStreamSample).Should(Succeed())
		Eventually(func(g Gomega) {
			_, err := first.Curl(serverIP)
			g.Expect(err).To(HaveOccurred())
		}).Should(Succeed())
		Consistently(func(g Gomega) {
			_, err := first.Curl(serverIP)
			g.Expect(err).To(HaveOccurred())
		}, 8*time.Second, 2*time.Second).Should(Succeed())
		assertVPNRouteReady(fix.vpc, first.onPremCIDR)
		first.AssertTunnelEstablished()
		nameAfter, uidAfter := first.GatewayPod(fix.namespace)
		Expect(nameAfter).To(Equal(podName))
		Expect(uidAfter).To(Equal(uid))

		acl.ReplaceACLRules("ingress", vpnACLRule("allow", first.onPremCIDR, first.siteTunnelIP, fix.natPublicIP))
		waitStreamGrows(fix.namespace, "stream-sink", policyStreamSink)
		assertVPNHTTPAllowed(first, serverIP)
		assertVPNRouteReady(fix.vpc, first.onPremCIDR)
		_, uidAfter = first.GatewayPod(fix.namespace)
		Expect(uidAfter).To(Equal(uid))
	})

	It("denies a VPN caller to a cross-Vpc shared Service while ordinary same-Vpc calls work", func() {
		Expect(applyManifest(podManifest(fix.namespace, "shared-backend", workerNodes[0], "", true))).To(Succeed())
		Expect(applyManifest(podManifest(fix.namespace, "shared-client", workerNodes[0], "", false))).To(Succeed())
		Expect(applyManifest(sharedServiceManifest(fix.namespace, "shared-service", "shared-backend", defaultVpcName, nil))).To(Succeed())
		DeferCleanup(func() {
			for _, name := range []string{"shared-service", "shared-backend", "shared-client"} {
				kind := "pod"
				if name == "shared-service" {
					kind = "service"
				}
				runBestEffort(repoRoot, "kubectl", "delete", kind, name, "-n", fix.namespace, "--ignore-not-found=true")
			}
		})
		waitPodsReady(fix.namespace, "shared-backend", "shared-client")
		waitServiceEndpoints(fix.namespace, "shared-service")
		serviceIP := vpnServiceIP(fix.namespace, "shared-service")
		assertVPNPodHTTPAllowed(fix.namespace, "shared-client", serviceIP, "welcome to nginx")
		assertVPNTunnelRoute(first, serviceIP)
		assertVPNHTTPDenied(first, serviceIP, mustPodIP(fix.namespace, "server"))
	})

	It("denies a VPN caller to a same-Vpc host-network Service backend", func() {
		Expect(applyManifest(fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: vpn-host-backend
  namespace: %s
  labels:
    app: vpn-host-backend
spec:
  hostNetwork: true
  nodeName: %s
  containers:
    - name: nginx
      image: nginx:1.27
`, fix.namespace, workerNodes[1]))).To(Succeed())
		Expect(applyManifest(serviceManifestWithVpc(fix.namespace, "vpn-host-service", "vpn-host-backend", fix.vpc))).To(Succeed())
		DeferCleanup(func() {
			runBestEffort(repoRoot, "kubectl", "delete", "service", "vpn-host-service", "-n", fix.namespace, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "pod", "vpn-host-backend", "-n", fix.namespace, "--ignore-not-found=true")
		})
		waitPodsReady(fix.namespace, "vpn-host-backend")
		waitServiceEndpoints(fix.namespace, "vpn-host-service")
		serviceIP := vpnServiceIP(fix.namespace, "vpn-host-service")
		assertVPNPodHTTPAllowed(fix.namespace, "client", serviceIP, "welcome to nginx")
		assertVPNTunnelRoute(first, serviceIP)
		assertVPNHTTPDenied(first, serviceIP, mustPodIP(fix.namespace, "server"))
	})

	It("keeps a second VPN live when the first site's tunnel goes down, without inter-site transit", func() {
		second := fix.AddSite("branch-two", "198.18.12.10", "198.18.12.0/24")
		fix.RouteSites()
		fix.Connect(second)
		second.StartServer()
		first.TerminateSA()
		Eventually(func(g Gomega) {
			_, err := first.Exec("swanctl", "--initiate", "--child", "branch")
			g.Expect(err).NotTo(HaveOccurred())
		}).Should(Succeed())
		EventualVPNReady(fix.namespace, first.name)
		waitResourceReady("routetable", waitVpcMainRouteTable(fix.vpc))
		assertVPNRouteReady(fix.vpc, second.onPremCIDR)
		serverIP := mustPodIP(fix.namespace, "server")
		assertVPNHTTPAllowed(first, serverIP)
		assertVPNHTTPAllowed(second, serverIP)
		assertVPNPodToSite(fix.namespace, "client", second)

		By("checking a VPN never advertises the other site's CIDR")
		for _, site := range []*vpnSite{first, second} {
			other := first
			if site == first {
				other = second
			}
			out, err := site.Exec("birdc", "-s", "/run/bird.ctl", "show", "route")
			Expect(err).NotTo(HaveOccurred())
			Expect(out).NotTo(ContainSubstring(other.onPremCIDR))
		}
		By("sending an inter-site packet into the tunnel and checking it cannot transit")
		_, err := first.Exec("ip", "route", "replace", second.onPremCIDR, "dev", "ipsec0")
		Expect(err).NotTo(HaveOccurred())
		assertVPNHTTPAllowed(first, serverIP)
		out, err := first.Curl(second.onPremIP + ":8080")
		Expect(err).To(HaveOccurred(), "unexpected inter-site response: %s", out)
		assertVPNHTTPAllowed(first, serverIP)

		By("stopping the first initiator and retaining the second site's packet delivery")
		Expect(run(repoRoot, "docker", "stop", first.peer)).To(Succeed())
		Eventually(func(g Gomega) {
			status, err := kubectlJSONPath(repoRoot, `{.status.conditions[?(@.type=="Ready")].status}`, "-n", fix.namespace, "get", "vpn", first.name)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(status).To(Equal("False"))
		}).Should(Succeed())
		assertVPNHTTPAllowed(second, serverIP)
		assertVPNPodToSite(fix.namespace, "client", second)
		Expect(run(repoRoot, "docker", "rm", "-f", first.peer)).To(Succeed())
		first.peerOwned = false
		_, err = dockerOutput("exec", vpnNATName, "ip", "link", "delete", fmt.Sprintf("jevn%d", first.privateIndex))
		Expect(err).NotTo(HaveOccurred())
		fix.Connect(first)
		first.StartServer()
	})

	It("withdraws and restores a direct peering return route when the gateway fails", func() {
		peeringCreated = true
		Expect(applyManifest(fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: %s
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: %s
spec:
  vpc: %s
  cidr: %s
---
apiVersion: juneau.loutres.me/v1alpha1
kind: VpcPeering
metadata:
  name: %s
spec:
  requester:
    vpc: %s
  accepter:
    vpc: %s
`, peerVpc, peerSubnet, peerVpc, peerCIDR, peering, fix.vpc, peerVpc))).To(Succeed())
		waitSubnetReady(peerSubnet)
		waitResourceReady("vpcpeering", peering)
		setMainRouteTableRoutes(fix.vpc, vpnRoute(first.onPremCIDR, fix.namespace, first.name), vpnRoute(fix.sites[1].onPremCIDR, fix.namespace, fix.sites[1].name), vpcPeeringRoute(peerCIDR, peering))
		setMainRouteTableRoutes(peerVpc, vpcPeeringRoute(first.onPremCIDR, peering))
		first.WaitGatewayAdvertises(fix.namespace, peerCIDR)
		first.TerminateSA()
		Eventually(func(g Gomega) {
			_, err := first.Exec("swanctl", "--initiate", "--child", "branch")
			g.Expect(err).NotTo(HaveOccurred())
		}).Should(Succeed())
		EventualVPNReady(fix.namespace, first.name)
		assertPeeringReturnRoute(peerVpc, first.onPremCIDR, true)
		Expect(applyManifest(podManifest(fix.namespace, "peer-server", workerNodes[0], peerSubnet, true))).To(Succeed())
		waitPodsReady(fix.namespace, "peer-server")
		assertVPNHTTPAllowed(first, mustPodIP(fix.namespace, "peer-server"))

		gateway, oldUID := first.GatewayPod(fix.namespace)
		Expect(run(repoRoot, "kubectl", "delete", "pod", gateway, "-n", fix.namespace, "--wait=true")).To(Succeed())
		assertPeeringReturnRoute(peerVpc, first.onPremCIDR, false)
		Eventually(func(g Gomega) {
			newUID, err := kubectlJSONPath(repoRoot, `{.metadata.uid}`, "-n", fix.namespace, "get", "pod", gateway)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(newUID).NotTo(BeEmpty())
			g.Expect(newUID).NotTo(Equal(oldUID))
		}).Should(Succeed())
		first.WaitGatewayAdvertises(fix.namespace, peerCIDR)
		first.TerminateSA()
		Eventually(func(g Gomega) {
			_, err := first.Exec("swanctl", "--initiate", "--child", "branch")
			g.Expect(err).NotTo(HaveOccurred())
		}).Should(Succeed())
		EventualVPNReady(fix.namespace, first.name)
		assertPeeringReturnRoute(peerVpc, first.onPremCIDR, true)
		assertVPNHTTPAllowed(first, mustPodIP(fix.namespace, "peer-server"))
	})

	It("uses an explicit default VPN route without stealing local Subnet or Service traffic", func() {
		const remoteIP = "203.0.113.7"
		Expect(applyManifest(serviceManifestWithVpc(fix.namespace, "local-service", "server", fix.vpc))).To(Succeed())
		DeferCleanup(func() {
			runBestEffort(repoRoot, "kubectl", "delete", "service", "local-service", "-n", fix.namespace, "--ignore-not-found=true")
		})
		waitServiceEndpoints(fix.namespace, "local-service")
		serviceIP := vpnServiceIP(fix.namespace, "local-service")
		_, err := first.Exec("ip", "addr", "add", remoteIP+"/32", "dev", "lo")
		Expect(err).NotTo(HaveOccurred())

		gateway, previousUID := first.GatewayPod(fix.namespace)
		setMainRouteTableRoutes(fix.vpc, vpnRoute("0.0.0.0/0", fix.namespace, first.name))
		initiatedUID := previousUID
		Eventually(func(g Gomega) {
			uid, err := kubectlJSONPath(repoRoot, `{.metadata.uid}`, "-n", fix.namespace, "get", "pod", gateway)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(uid).NotTo(BeEmpty())
			if uid != initiatedUID {
				phase, err := kubectlJSONPath(repoRoot, `{.status.phase}`, "-n", fix.namespace, "get", "pod", gateway)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(phase).To(Equal("Running"))
				sas, err := first.Exec("swanctl", "--list-sas")
				g.Expect(err).NotTo(HaveOccurred())
				if strings.Contains(sas, "branch: #") {
					_, err = first.Exec("swanctl", "--terminate", "--ike", "branch", "--force")
					g.Expect(err).NotTo(HaveOccurred())
				}
				_, err = first.Exec("swanctl", "--initiate", "--child", "branch")
				g.Expect(err).NotTo(HaveOccurred())
				initiatedUID = uid
			}
			ready, err := kubectlJSONPath(repoRoot, `{.status.conditions[?(@.type=="Ready")].status}`, "-n", fix.namespace, "get", "vpn", first.name)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(ready).To(Equal("True"))
		}, kindKubectlTimeout, 5*time.Second).Should(Succeed())
		configured, err := kubectlJSONPath(repoRoot, `{.spec.containers[0].env[?(@.name=="VPN_REMOTE_ROUTES")].value}`, "-n", fix.namespace, "get", "pod", gateway)
		Expect(err).NotTo(HaveOccurred())
		Expect(configured).To(Equal(`["0.0.0.0/0"]`))
		assertVPNRouteReady(fix.vpc, "0.0.0.0/0")
		assertVPNPodToSiteAddress(fix.namespace, "client", remoteIP)
		assertVPNHTTPAllowed(first, mustPodIP(fix.namespace, "server"))
		assertVPNTunnelRoute(first, serviceIP)
		assertVPNHTTPAllowed(first, serviceIP)
		assertVPNPodHTTPAllowed(fix.namespace, "client", serviceIP, "welcome to nginx")
		assertVPNPodHTTPAllowed(fix.namespace, "client", mustPodIP(fix.namespace, "server"), "welcome to nginx")
	})
})

func vpnACLRule(action, cidr, tunnelIP, natPublicIP string) string {
	return fmt.Sprintf(`
  ingress:
    - priority: 100
      action: %s
      protocol: tcp
      cidr: %s
      ports:
        - port: 80
        - port: 9000
    - priority: 200
      action: allow
      protocol: tcp
      cidr: %s/32
    - priority: 300
      action: allow
      protocol: udp
      cidr: %s/32
      ports:
        - port: 500
        - port: 4500
  egress:
    - priority: 100
      action: allow
      protocol: all
      cidr: 0.0.0.0/0`, action, cidr, tunnelIP, natPublicIP)
}

func assertVPNHTTPAllowed(site *vpnSite, address string) {
	Eventually(func(g Gomega) {
		out, err := site.Curl(address)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.ToLower(out)).To(ContainSubstring("welcome to nginx"))
	}).Should(Succeed())
}

func assertVPNPodToSite(namespace, pod string, site *vpnSite) {
	assertVPNPodToSiteAddress(namespace, pod, site.onPremIP)
}

func assertVPNPodToSiteAddress(namespace, pod, ip string) {
	want := mustPodIP(namespace, pod)
	Eventually(func(g Gomega) {
		out, err := kubectlOutput(repoRoot, "exec", "-n", namespace, pod, "--", "curl", "--noproxy", "*", "-fsS", "--max-time", "3", "http://"+ip+":8080")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(out).To(Equal(want))
	}).Should(Succeed())
}

func assertVPNPodHTTPAllowed(namespace, pod, address, body string) {
	Eventually(func(g Gomega) {
		out, err := kubectlOutput(repoRoot, "exec", "-n", namespace, pod, "--", "curl", "--noproxy", "*", "-fsS", "--max-time", "3", "http://"+address)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.ToLower(out)).To(ContainSubstring(body))
	}).Should(Succeed())
}

func vpnServiceIP(namespace, name string) string {
	ip, err := kubectlJSONPath(repoRoot, `{.spec.clusterIP}`, "-n", namespace, "get", "service", name)
	Expect(err).NotTo(HaveOccurred())
	Expect(strings.TrimSpace(ip)).NotTo(BeEmpty())
	return strings.TrimSpace(ip)
}

func assertVPNTunnelRoute(site *vpnSite, ip string) {
	_, err := site.Exec("ip", "route", "replace", ip+"/32", "dev", "ipsec0", "src", site.onPremIP)
	Expect(err).NotTo(HaveOccurred())
	out, err := site.Exec("ip", "route", "get", ip, "from", site.onPremIP)
	Expect(err).NotTo(HaveOccurred())
	Expect(out).To(ContainSubstring("dev ipsec0"))
}

func assertVPNHTTPDenied(site *vpnSite, address, reachableAddress string) {
	for range 3 {
		assertVPNHTTPAllowed(site, reachableAddress)
		site.AssertTunnelEstablished()
		out, err := site.Curl(address)
		Expect(err).To(HaveOccurred(), "unexpected VPN response: %s", out)
	}
	assertVPNHTTPAllowed(site, reachableAddress)
}

func assertVPNRouteReady(vpc, dst string) {
	Eventually(func(g Gomega) {
		out, err := kubectlJSONPath(repoRoot, fmt.Sprintf(`{.status.routes[?(@.dst=="%s")].via.type}`, dst), "get", "routetable", waitVpcMainRouteTable(vpc))
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(out).To(Equal("vpn"))
	}).Should(Succeed())
}

func assertPeeringReturnRoute(vpc, dst string, present bool) {
	Eventually(func(g Gomega) {
		out, err := kubectlJSONPath(repoRoot, fmt.Sprintf(`{.status.routes[?(@.dst=="%s")].dst}`, dst), "get", "routetable", waitVpcMainRouteTable(vpc))
		g.Expect(err).NotTo(HaveOccurred())
		if present {
			reason, err := kubectlJSONPath(repoRoot, `{.status.conditions[?(@.type=="Ready")].reason}`, "get", "routetable", waitVpcMainRouteTable(vpc))
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(out).To(Equal(dst), "return RouteTable %s reason: %s", vpc, reason)
		} else {
			g.Expect(out).To(BeEmpty())
		}
	}).Should(Succeed())
}
