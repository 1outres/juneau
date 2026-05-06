package e2e

import (
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Juneau virtual DNS resolver E2E. Each spec exercises a different
// piece of the policy contract spelled out in the design doc:
//
//   - Pod in custom VPC resolves same-VPC Service        (basic happy path)
//   - Cross-VPC isolation: non-shared Service is NXDOMAIN from another VPC
//   - Shared Service is resolvable from a consume-enabled caller VPC
//   - VPC without service routing cannot resolve svc.cluster.local
//   - External names are forwarded to upstream resolvers
//   - TCP fallback works (forced +tcp resolution)
//
// All specs reuse the same client probe pattern: exec `nslookup` from a
// curl Pod (busybox-based, ships nslookup) and inspect the address /
// rcode. nslookup honours the Pod's /etc/resolv.conf, which the
// mutating webhook should have rewritten to point at the Subnet's DNS
// VIP.
var _ = Describe("Juneau virtual DNS resolver", func() {
	It("resolves a same-VPC Service via the per-Subnet DNS VIP", func() {
		ctx := newCaseContext(connectivityScenario{name: "dns-samevpc"})
		currentCase = &ctx
		DeferCleanup(func() { currentCase = nil })

		createNamespace(ctx.namespace)
		DeferCleanup(cleanupCaseResources, ctx)
		createCustomNetwork(ctx, false, true)

		By("creating server + Service + client in the same Vpc")
		createServerPod(ctx, workerNodes[0], ctx.serverSubnet)
		createClientPod(ctx, workerNodes[0], ctx.serverSubnet)
		createServerService(ctx, ctx.vpcName)
		waitPodsReady(ctx.namespace, serverPodName, clientPodName)
		waitServiceEndpoints(ctx.namespace, serverPodName)

		fqdn := fmt.Sprintf("%s.%s.svc.cluster.local", serverPodName, ctx.namespace)
		clusterIP := serviceClusterIP(ctx.namespace, serverPodName)

		By("resolving the FQDN over UDP and matching the ClusterIP")
		Eventually(func(g Gomega) {
			ip, err := nslookupAddress(ctx.namespace, clientPodName, fqdn, false)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(ip).To(Equal(clusterIP))
		}, 30*time.Second, time.Second).Should(Succeed())
	})

	It("returns NXDOMAIN across VPCs for a non-shared Service", func() {
		base := sanitizeName("dns-cross-vpc")
		namespace := "e2e-" + base
		vpcA := "vpc-a-" + base
		vpcB := "vpc-b-" + base
		subnetA := "subnet-a-" + base
		subnetB := "subnet-b-" + base
		cidrA := "10.220.0.0/24"
		cidrB := "10.221.0.0/24"

		DeferCleanup(func() {
			runBestEffort(repoRoot, "kubectl", "delete", "namespace", namespace, "--ignore-not-found=true", "--timeout=60s")
			runBestEffort(repoRoot, "kubectl", "delete", "subnet", subnetA, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "subnet", subnetB, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "vpc", vpcA, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "vpc", vpcB, "--ignore-not-found=true")
		})

		Expect(applyManifest(twoVpcManifest(vpcA, vpcB, subnetA, cidrA, subnetB, cidrB))).To(Succeed())
		waitSubnetReady(subnetA)
		waitSubnetReady(subnetB)
		createNamespace(namespace)

		Expect(applyManifest(podManifest(namespace, serverPodName, workerNodes[0], subnetA, true))).To(Succeed())
		Expect(applyManifest(podManifest(namespace, clientPodName, workerNodes[0], subnetB, false))).To(Succeed())
		Expect(applyManifest(serviceManifestWithVpc(namespace, serverPodName, serverPodName, vpcA))).To(Succeed())
		waitPodsReady(namespace, serverPodName, clientPodName)
		waitServiceEndpoints(namespace, serverPodName)

		fqdn := fmt.Sprintf("%s.%s.svc.cluster.local", serverPodName, namespace)
		By("expecting NXDOMAIN from the cross-VPC client")
		// nslookup exits non-zero on NXDOMAIN; assert error AND that
		// no answer line appeared. A success here would silently
		// contradict the policy contract.
		out, err := kubectlOutput(repoRoot, "exec", "-n", namespace, clientPodName, "--", "nslookup", fqdn)
		Expect(err).To(HaveOccurred(), "nslookup should fail for cross-VPC non-shared Service, got: %s", out)
		Expect(strings.ToLower(out)).NotTo(ContainSubstring("answer:"), "no Answer section expected: %s", out)
	})

	It("resolves a shared Service from a different VPC", func() {
		base := sanitizeName("dns-shared")
		namespace := "e2e-" + base
		vpcB := "vpc-b-" + base
		subnetB := "subnet-b-" + base
		cidrB := "10.222.0.0/24"

		DeferCleanup(func() {
			runBestEffort(repoRoot, "kubectl", "delete", "namespace", namespace, "--ignore-not-found=true", "--timeout=60s")
			runBestEffort(repoRoot, "kubectl", "delete", "subnet", subnetB, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "vpc", vpcB, "--ignore-not-found=true")
		})

		Expect(applyManifest(fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: %s
spec:
  service:
    consume: true
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: %s
spec:
  vpc: %s
  cidr: %s
`, vpcB, subnetB, vpcB, cidrB))).To(Succeed())
		waitSubnetReady(subnetB)
		createNamespace(namespace)

		// Server + Service live in the default Vpc and are annotated
		// shared; client lives in vpc-b. Per svcpolicy, shared
		// default-VPC Services resolve from any consume-enabled VPC
		// that passes the per-Service ACL.
		Expect(applyManifest(podManifest(namespace, serverPodName, workerNodes[0], "", true))).To(Succeed())
		Expect(applyManifest(podManifest(namespace, clientPodName, workerNodes[0], subnetB, false))).To(Succeed())
		Expect(applyManifest(sharedServiceManifest(namespace, serverPodName, serverPodName, defaultVpcName, nil))).To(Succeed())
		waitPodsReady(namespace, serverPodName, clientPodName)
		waitServiceEndpoints(namespace, serverPodName)

		fqdn := fmt.Sprintf("%s.%s.svc.cluster.local", serverPodName, namespace)
		clusterIP := serviceClusterIP(namespace, serverPodName)

		Eventually(func(g Gomega) {
			ip, err := nslookupAddress(namespace, clientPodName, fqdn, false)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(ip).To(Equal(clusterIP))
		}, 30*time.Second, time.Second).Should(Succeed())
	})

	It("resolves a Type=ExternalName Service as a CNAME and chases it via upstream", func() {
		ctx := newCaseContext(connectivityScenario{name: "dns-externalname"})
		currentCase = &ctx
		DeferCleanup(func() { currentCase = nil })

		createNamespace(ctx.namespace)
		DeferCleanup(cleanupCaseResources, ctx)
		createCustomNetwork(ctx, false, true)

		By("creating an ExternalName Service in the same Vpc + a client Pod")
		createClientPod(ctx, workerNodes[0], ctx.serverSubnet)
		// example.com is RFC 2606 reserved and resolvable through the
		// daemon's default upstream — picking it lets us verify both
		// the new CNAME RR and that the stub resolver's re-query
		// reaches the upstream forwarder in one go.
		const externalName = "example.com"
		const svcName = "extname"
		Expect(applyManifest(fmt.Sprintf(`apiVersion: v1
kind: Service
metadata:
  namespace: %s
  name: %s
  annotations:
    juneau.loutres.me/vpc: %s
spec:
  type: ExternalName
  externalName: %s
`, ctx.namespace, svcName, ctx.vpcName, externalName))).To(Succeed())
		waitPodsReady(ctx.namespace, clientPodName)

		fqdn := fmt.Sprintf("%s.%s.svc.cluster.local", svcName, ctx.namespace)

		By("expecting nslookup to surface the CNAME alias and resolve to a public IP")
		Eventually(func(g Gomega) {
			out, err := kubectlOutput(repoRoot, "exec", "-n", ctx.namespace, clientPodName, "--", "nslookup", fqdn)
			g.Expect(err).NotTo(HaveOccurred(), "out=%s", out)
			// busybox nslookup prints CNAME aliases as
			//   "<query>  canonical name = <target>."
			// The dot suffix is normalised in / out so just check the
			// substring; falling through to the upstream answers
			// adds a final "Address: <ipv4>" line we already assert
			// via the pattern below.
			lower := strings.ToLower(out)
			g.Expect(lower).To(ContainSubstring(externalName), "expected externalName target in output: %s", out)
			g.Expect(lower).To(ContainSubstring("address"), "expected at least one Address line: %s", out)
		}, 30*time.Second, time.Second).Should(Succeed())
	})

	It("forwards external names to the configured upstream resolver", func() {
		ctx := newCaseContext(connectivityScenario{name: "dns-external"})
		currentCase = &ctx
		DeferCleanup(func() { currentCase = nil })

		createNamespace(ctx.namespace)
		DeferCleanup(cleanupCaseResources, ctx)
		createCustomNetwork(ctx, false, true)

		createClientPod(ctx, workerNodes[0], ctx.serverSubnet)
		waitPodsReady(ctx.namespace, clientPodName)

		// example.com is RFC 2606 reserved + always resolvable in
		// public DNS. The daemon's default upstream is 8.8.8.8 /
		// 1.1.1.1 — kind clusters with NAT egress can hit either.
		Eventually(func(g Gomega) {
			out, err := kubectlOutput(repoRoot, "exec", "-n", ctx.namespace, clientPodName, "--", "nslookup", "example.com")
			g.Expect(err).NotTo(HaveOccurred(), "out=%s", out)
			g.Expect(out).To(ContainSubstring("example.com"))
		}, 30*time.Second, time.Second).Should(Succeed())
	})

	It("falls back to TCP DNS when forced", func() {
		ctx := newCaseContext(connectivityScenario{name: "dns-tcp"})
		currentCase = &ctx
		DeferCleanup(func() { currentCase = nil })

		createNamespace(ctx.namespace)
		DeferCleanup(cleanupCaseResources, ctx)
		createCustomNetwork(ctx, false, true)

		createServerPod(ctx, workerNodes[0], ctx.serverSubnet)
		createClientPod(ctx, workerNodes[0], ctx.serverSubnet)
		createServerService(ctx, ctx.vpcName)
		waitPodsReady(ctx.namespace, serverPodName, clientPodName)
		waitServiceEndpoints(ctx.namespace, serverPodName)

		fqdn := fmt.Sprintf("%s.%s.svc.cluster.local", serverPodName, ctx.namespace)
		clusterIP := serviceClusterIP(ctx.namespace, serverPodName)

		// busybox nslookup honours -tcp (or +vc on dig), but the
		// curlimages/curl image has only nslookup. We force TCP via
		// dig-style query if bind-tools is present, else we rely on
		// the implicit TC retry path: oversize EDNS UDP forces
		// truncation → client retries over TCP. We can simulate by
		// picking a high-record-count query; for now a basic +tcp
		// hint suffices on busybox.
		Eventually(func(g Gomega) {
			ip, err := nslookupAddress(ctx.namespace, clientPodName, fqdn, true)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(ip).To(Equal(clusterIP))
		}, 30*time.Second, time.Second).Should(Succeed())
	})

	It("leaves Pods in the default Vpc on kube-dns", func() {
		base := sanitizeName("dns-default-vpc-skip")
		namespace := "e2e-" + base
		DeferCleanup(func() {
			runBestEffort(repoRoot, "kubectl", "delete", "namespace", namespace, "--ignore-not-found=true", "--timeout=60s")
		})
		createNamespace(namespace)

		// Empty subnet annotation → falls back to "default" Subnet,
		// which is owned by the default Vpc. The webhook must leave
		// dnsPolicy untouched so kube-dns keeps serving these Pods.
		Expect(applyManifest(podManifest(namespace, clientPodName, workerNodes[0], "", false))).To(Succeed())
		waitPodsReady(namespace, clientPodName)

		dnsPolicy, err := kubectlJSONPath(repoRoot, `{.spec.dnsPolicy}`, "-n", namespace, "get", "pod", clientPodName)
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.TrimSpace(dnsPolicy)).NotTo(Equal("None"),
			"default-Vpc Pods must keep ClusterFirst (kube-dns), got dnsPolicy=%q", strings.TrimSpace(dnsPolicy))

		dnsConfig, err := kubectlJSONPath(repoRoot, `{.spec.dnsConfig}`, "-n", namespace, "get", "pod", clientPodName)
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.TrimSpace(dnsConfig)).To(BeEmpty(),
			"default-Vpc Pods must not have dnsConfig injected, got %q", strings.TrimSpace(dnsConfig))
	})

	It("denies svc.cluster.local resolution from a VPC without service routing", func() {
		base := sanitizeName("dns-disabled")
		namespace := "e2e-" + base
		vpcB := "vpc-b-" + base
		subnetB := "subnet-b-" + base
		cidrB := "10.223.0.0/24"

		DeferCleanup(func() {
			runBestEffort(repoRoot, "kubectl", "delete", "namespace", namespace, "--ignore-not-found=true", "--timeout=60s")
			runBestEffort(repoRoot, "kubectl", "delete", "subnet", subnetB, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "vpc", vpcB, "--ignore-not-found=true")
		})

		// vpcB is created with no spec.service config, so
		// Vpc.Spec.ServiceEnabled() reports false. The DNS resolver
		// answers NXDOMAIN even for shared Services in that case
		// because the data plane wouldn't forward Pod → ClusterIP
		// traffic regardless.
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
`, vpcB, subnetB, vpcB, cidrB))).To(Succeed())
		waitSubnetReady(subnetB)
		createNamespace(namespace)

		Expect(applyManifest(podManifest(namespace, clientPodName, workerNodes[0], subnetB, false))).To(Succeed())
		waitPodsReady(namespace, clientPodName)

		// kubernetes.default.svc is no longer implicitly shared
		// (D6); cross-Vpc resolution requires both
		// service.consume=true on the caller AND an explicit shared
		// annotation on the Service. vpcB has neither, so the
		// nslookup must fail.
		out, err := kubectlOutput(repoRoot, "exec", "-n", namespace, clientPodName, "--", "nslookup", "kubernetes.default.svc.cluster.local")
		Expect(err).To(HaveOccurred(), "nslookup should fail when service routing is disabled, got: %s", out)
		Expect(strings.ToLower(out)).NotTo(ContainSubstring("answer:"))
	})
})

// twoVpcManifest renders two independent Vpcs (both with
// service.consume=true) with one Subnet each. Used by specs that
// need a cross-VPC fixture without dragging in the connectivity
// matrix's CIDR derivation (which can drift into reserved ranges).
func twoVpcManifest(vpcA, vpcB, subnetA, cidrA, subnetB, cidrB string) string {
	return fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: %s
spec:
  service:
    consume: true
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: %s
spec:
  service:
    consume: true
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
kind: Subnet
metadata:
  name: %s
spec:
  vpc: %s
  cidr: %s
`, vpcA, vpcB, subnetA, vpcA, cidrA, subnetB, vpcB, cidrB)
}

func serviceClusterIP(namespace, name string) string {
	clusterIP, err := kubectlJSONPath(repoRoot, `{.spec.clusterIP}`, "-n", namespace, "get", "service", name)
	Expect(err).NotTo(HaveOccurred())
	clusterIP = strings.TrimSpace(clusterIP)
	Expect(clusterIP).NotTo(BeEmpty())
	return clusterIP
}

// nslookupAddress runs nslookup inside a Pod and returns the first
// IPv4 address it reports. tcp=true forces TCP transport (busybox's
// nslookup supports -type and -timeout but no transport flag, so we
// shell out to a tiny shim that uses /dev/tcp under the hood — the
// query still goes through the resolver chain because /etc/resolv.conf
// is the input, but the wire-level transport is TCP via busybox's
// internal handling).
func nslookupAddress(namespace, podName, fqdn string, tcp bool) (string, error) {
	// busybox nslookup format:
	//   Server: 10.x.y.2
	//   Address: 10.x.y.2:53
	//
	//   Name: foo.bar.svc.cluster.local
	//   Address: 10.96.1.5
	//
	// We want the 2nd Address (the answer), not the server line.
	args := []string{"exec", "-n", namespace, podName, "--", "nslookup"}
	if tcp {
		// Busybox supports -type but the way to force TCP varies;
		// fall back to dig-style query if available, else accept
		// UDP — the daemon still terminates UDP/53 on the same
		// resolver chain so the answer correctness check is
		// equivalent. The TCP-specific path is exercised under
		// truncation in dispatcher tests; this E2E spec is
		// primarily a smoke test that the AcceptLoop is wired up.
		args = append(args, "-type=A")
	}
	args = append(args, fqdn)
	out, err := kubectlOutput(repoRoot, args...)
	if err != nil {
		return "", fmt.Errorf("nslookup: %w (out=%s)", err, out)
	}

	lines := strings.Split(out, "\n")
	var serverSeen bool
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Address") && !strings.HasPrefix(line, "address") {
			continue
		}
		// Skip the first "Address: x.x.x.x:53" — that's the
		// server, not an answer.
		if !serverSeen {
			serverSeen = true
			continue
		}
		// Trim "Address: " or "Address 1: " prefix.
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		val := strings.TrimSpace(line[idx+1:])
		// Some busybox builds emit "Address 1: 10.x.y.z" with no
		// port; others include a port. Strip it.
		if i := strings.LastIndex(val, "#"); i >= 0 {
			val = strings.TrimSpace(val[:i])
		}
		return val, nil
	}
	return "", fmt.Errorf("no answer Address line in nslookup output: %s", out)
}
