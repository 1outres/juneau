package e2e

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Juneau VPC-private DNS", func() {
	It("publishes and converges a Deployment PodSelector RRset inside its Vpc", func() {
		fixture := newPrivateDNSFixture("dns-private-selector")
		currentCase = &caseContext{namespace: fixture.namespace}
		DeferCleanup(func() { currentCase = nil })
		DeferCleanup(cleanupPrivateDNSFixture, fixture)

		createNamespace(fixture.namespace)
		Expect(applyManifest(twoVpcManifest(
			fixture.vpc, fixture.foreignVpc,
			fixture.subnet, fixture.cidr,
			fixture.foreignSubnet, fixture.foreignCIDR,
		))).To(Succeed())
		waitSubnetReady(fixture.subnet)
		waitSubnetReady(fixture.foreignSubnet)

		Expect(applyManifest(privateDNSDeploymentManifest(fixture))).To(Succeed())
		Expect(applyManifest(netshootPodManifest(fixture.namespace, fixture.client, workerNodes[0], fixture.subnet))).To(Succeed())
		Expect(applyManifest(netshootPodManifest(fixture.namespace, fixture.foreignClient, workerNodes[0], fixture.foreignSubnet))).To(Succeed())
		waitDeploymentReadyReplicas(fixture.namespace, fixture.deployment, 3)
		waitPodsReady(fixture.namespace, fixture.client, fixture.foreignClient)

		dnsResources, err := privateDNSResourcesManifest(fixture)
		Expect(err).NotTo(HaveOccurred())
		Expect(applyManifest(dnsResources)).To(Succeed())
		waitResourceReady("dnszone", fixture.zone)
		waitResourceReady("dnszone", fixture.foreignZone)

		resolver := subnetDNS(fixture.subnet)
		foreignResolver := subnetDNS(fixture.foreignSubnet)
		fqdn := fmt.Sprintf("%s.%s.", fixture.recordOwner, fixture.domain)

		By("waiting for one PodSelector source to publish all three Ready Deployment NICs")
		initialAddresses := waitDNSRecordAddresses(fixture, 3)
		assertDNSAAnswers(fixture.namespace, fixture.client, resolver, fqdn, 30, initialAddresses)

		By("proving the same private suffix resolves to a different fixed address in another Vpc")
		foreignAddresses := waitFixedDNSRecordAddress(fixture.foreignRecord, fixture.foreignAddress)
		assertDNSAAnswers(fixture.namespace, fixture.foreignClient, foreignResolver, fqdn, 30, foreignAddresses)

		By("returning an authoritative NXDOMAIN for an unknown owner in the private zone")
		assertAuthoritativeNXDomain(fixture.namespace, fixture.client, resolver, "missing."+fixture.domain+".")

		By("scaling down without changing the DNSRecord and removing one address from the RRset")
		Expect(run(repoRoot, "kubectl", "scale", "deployment", "-n", fixture.namespace, fixture.deployment, "--replicas=2")).To(Succeed())
		waitDeploymentReadyReplicas(fixture.namespace, fixture.deployment, 2)
		scaledAddresses := waitDNSRecordAddresses(fixture, 2)
		assertDNSAAnswers(fixture.namespace, fixture.client, resolver, fqdn, 30, scaledAddresses)

		By("scaling back up and publishing all three current Pod NIC addresses")
		Expect(run(repoRoot, "kubectl", "scale", "deployment", "-n", fixture.namespace, fixture.deployment, "--replicas=3")).To(Succeed())
		waitDeploymentReadyReplicas(fixture.namespace, fixture.deployment, 3)
		restoredAddresses := waitDNSRecordAddresses(fixture, 3)
		assertDNSAAnswers(fixture.namespace, fixture.client, resolver, fqdn, 30, restoredAddresses)
	})
})

type privateDNSFixture struct {
	namespace      string
	vpc            string
	foreignVpc     string
	subnet         string
	foreignSubnet  string
	cidr           string
	foreignCIDR    string
	deployment     string
	client         string
	foreignClient  string
	zone           string
	foreignZone    string
	record         string
	foreignRecord  string
	recordOwner    string
	domain         string
	selectorKey    string
	selectorValue  string
	foreignAddress string
}

func newPrivateDNSFixture(name string) privateDNSFixture {
	base := sanitizeName(name)
	return privateDNSFixture{
		namespace:      "e2e-" + base,
		vpc:            "vpc-a-" + base,
		foreignVpc:     "vpc-b-" + base,
		subnet:         "subnet-a-" + base,
		foreignSubnet:  "subnet-b-" + base,
		cidr:           cidrForScenario(base, 0),
		foreignCIDR:    cidrForScenario(base, 1),
		deployment:     "dns-backend",
		client:         "dns-client",
		foreignClient:  "dns-foreign-client",
		zone:           "zone-a-" + base,
		foreignZone:    "zone-b-" + base,
		record:         "record-a-" + base,
		foreignRecord:  "record-b-" + base,
		recordOwner:    "backends",
		domain:         base + ".test",
		selectorKey:    "dns-test",
		selectorValue:  base,
		foreignAddress: "192.0.2.53",
	}
}

func (f privateDNSFixture) podSelector() string {
	return f.selectorKey + "=" + f.selectorValue
}

func cleanupPrivateDNSFixture(f privateDNSFixture) {
	runBestEffort(repoRoot, "kubectl", "delete", "dnsrecord", f.record, f.foreignRecord, "--ignore-not-found=true")
	runBestEffort(repoRoot, "kubectl", "delete", "dnszone", f.zone, f.foreignZone, "--ignore-not-found=true")
	runBestEffort(repoRoot, "kubectl", "delete", "namespace", f.namespace, "--ignore-not-found=true", "--timeout=60s")
	runBestEffort(repoRoot, "kubectl", "delete", "subnet", f.subnet, f.foreignSubnet, "--ignore-not-found=true")
	runBestEffort(repoRoot, "kubectl", "delete", "vpc", f.vpc, f.foreignVpc, "--ignore-not-found=true")
}

func privateDNSResourcesManifest(f privateDNSFixture) (string, error) {
	fixedAddress := f.foreignAddress
	objects := []any{
		&juneauv1alpha1.DNSZone{
			TypeMeta:   metav1.TypeMeta{APIVersion: juneauv1alpha1.GroupVersion.String(), Kind: "DNSZone"},
			ObjectMeta: metav1.ObjectMeta{Name: f.zone},
			Spec:       juneauv1alpha1.DNSZoneSpec{Vpc: f.vpc, Domain: f.domain},
		},
		&juneauv1alpha1.DNSZone{
			TypeMeta:   metav1.TypeMeta{APIVersion: juneauv1alpha1.GroupVersion.String(), Kind: "DNSZone"},
			ObjectMeta: metav1.ObjectMeta{Name: f.foreignZone},
			Spec:       juneauv1alpha1.DNSZoneSpec{Vpc: f.foreignVpc, Domain: f.domain},
		},
		&juneauv1alpha1.DNSRecord{
			TypeMeta:   metav1.TypeMeta{APIVersion: juneauv1alpha1.GroupVersion.String(), Kind: "DNSRecord"},
			ObjectMeta: metav1.ObjectMeta{Name: f.record},
			Spec: juneauv1alpha1.DNSRecordSpec{
				Zone: f.zone,
				Name: f.recordOwner,
				Type: juneauv1alpha1.DNSRecordTypeA,
				Sources: []juneauv1alpha1.DNSRecordSource{{PodSelector: &juneauv1alpha1.DNSPodSelectorSource{
					Namespace: f.namespace,
					Interface: podIfaceName,
					Selector:  metav1.LabelSelector{MatchLabels: map[string]string{f.selectorKey: f.selectorValue}},
				}}},
			},
		},
		&juneauv1alpha1.DNSRecord{
			TypeMeta:   metav1.TypeMeta{APIVersion: juneauv1alpha1.GroupVersion.String(), Kind: "DNSRecord"},
			ObjectMeta: metav1.ObjectMeta{Name: f.foreignRecord},
			Spec: juneauv1alpha1.DNSRecordSpec{
				Zone:    f.foreignZone,
				Name:    f.recordOwner,
				Type:    juneauv1alpha1.DNSRecordTypeA,
				Sources: []juneauv1alpha1.DNSRecordSource{{IP: &fixedAddress}},
			},
		},
	}

	var documents strings.Builder
	for i, object := range objects {
		encoded, err := json.Marshal(object)
		if err != nil {
			return "", fmt.Errorf("encode private DNS resource %d: %w", i, err)
		}
		if i > 0 {
			documents.WriteString("---\n")
		}
		documents.Write(encoded)
		documents.WriteByte('\n')
	}
	return documents.String(), nil
}

func privateDNSDeploymentManifest(f privateDNSFixture) string {
	return fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  namespace: %s
  name: %s
spec:
  replicas: 3
  selector:
    matchLabels:
      %s: %s
  template:
    metadata:
      labels:
        %s: %s
      annotations:
        juneau.loutres.me/subnet: %s
    spec:
      terminationGracePeriodSeconds: 0
      containers:
        - name: server
          image: nginx:1.27
          ports:
            - containerPort: 80
`, f.namespace, f.deployment, f.selectorKey, f.selectorValue, f.selectorKey, f.selectorValue, f.subnet)
}

func waitDeploymentReadyReplicas(namespace, name string, replicas int32) {
	Eventually(func(g Gomega) {
		out, err := kubectlOutput(repoRoot, "get", "deployment", "-n", namespace, name, "-o", "json")
		g.Expect(err).NotTo(HaveOccurred())

		var deployment struct {
			Metadata struct {
				Generation int64 `json:"generation"`
			} `json:"metadata"`
			Status struct {
				ObservedGeneration int64 `json:"observedGeneration"`
				ReadyReplicas      int32 `json:"readyReplicas"`
				UpdatedReplicas    int32 `json:"updatedReplicas"`
				AvailableReplicas  int32 `json:"availableReplicas"`
			} `json:"status"`
		}
		g.Expect(json.Unmarshal([]byte(out), &deployment)).To(Succeed())
		g.Expect(deployment.Status.ObservedGeneration).To(BeNumerically(">=", deployment.Metadata.Generation))
		g.Expect(deployment.Status.ReadyReplicas).To(Equal(replicas))
		g.Expect(deployment.Status.UpdatedReplicas).To(Equal(replicas))
		g.Expect(deployment.Status.AvailableReplicas).To(Equal(replicas))
	}).Should(Succeed())
}

func waitDNSRecordAddresses(f privateDNSFixture, count int) []string {
	var expected []string
	Eventually(func(g Gomega) {
		addresses, err := readyPodNICAddresses(f.namespace, f.podSelector())
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(addresses).To(HaveLen(count))

		record, err := getDNSRecord(f.record)
		g.Expect(err).NotTo(HaveOccurred())
		expectReadyDNSRecord(g, record, addresses)
		expected = append(expected[:0], addresses...)
	}).Should(Succeed())
	return expected
}

func waitFixedDNSRecordAddress(recordName, address string) []string {
	expected := []string{address}
	Eventually(func(g Gomega) {
		record, err := getDNSRecord(recordName)
		g.Expect(err).NotTo(HaveOccurred())
		expectReadyDNSRecord(g, record, expected)
	}).Should(Succeed())
	return expected
}

func expectReadyDNSRecord(g Gomega, record *juneauv1alpha1.DNSRecord, expected []string) {
	g.Expect(record.Status.ObservedGeneration).To(Equal(record.Generation))
	g.Expect(hasReadyCondition(record.Status.Conditions, juneauv1alpha1.DNSRecordConditionReady, record.Generation)).To(BeTrue())
	g.Expect(record.Spec.TTL).NotTo(BeNil())
	g.Expect(*record.Spec.TTL).To(Equal(int32(30)))
	g.Expect(record.Status.Addresses).To(ConsistOf(expected))
}

func getDNSRecord(name string) (*juneauv1alpha1.DNSRecord, error) {
	out, err := kubectlOutput(repoRoot, "get", "dnsrecord", name, "-o", "json")
	if err != nil {
		return nil, err
	}
	var record juneauv1alpha1.DNSRecord
	if err := json.Unmarshal([]byte(out), &record); err != nil {
		return nil, fmt.Errorf("decode DNSRecord %s: %w", name, err)
	}
	return &record, nil
}

func readyPodNICAddresses(namespace, selector string) ([]string, error) {
	out, err := kubectlOutput(repoRoot, "get", "pods", "-n", namespace, "-l", selector, "-o", "json")
	if err != nil {
		return nil, err
	}
	var pods corev1.PodList
	if err := json.Unmarshal([]byte(out), &pods); err != nil {
		return nil, fmt.Errorf("decode selected Pods: %w", err)
	}

	addresses := make([]string, 0, len(pods.Items))
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !pod.DeletionTimestamp.IsZero() || !podReady(pod) {
			continue
		}

		nic, err := getNetworkInterface(namespace, pod.Name+"."+podIfaceName)
		if err != nil {
			return nil, err
		}
		if nic.Spec.PodRef.Name != pod.Name || nic.Spec.PodRef.UID != string(pod.UID) || nic.Spec.PodRef.Interface != podIfaceName {
			return nil, fmt.Errorf("NetworkInterface %s/%s does not refer to current Pod %s", namespace, nic.Name, pod.Name)
		}
		if nic.Status.ObservedGeneration != nic.Generation || !hasReadyCondition(nic.Status.Conditions, juneauv1alpha1.NetworkInterfaceStatusReady, nic.Generation) {
			return nil, fmt.Errorf("NetworkInterface %s/%s is not Ready for generation %d", namespace, nic.Name, nic.Generation)
		}
		address, _, err := net.ParseCIDR(nic.Status.Address)
		if err != nil || address.To4() == nil {
			return nil, fmt.Errorf("NetworkInterface %s/%s has invalid IPv4 status address %q", namespace, nic.Name, nic.Status.Address)
		}
		if address.String() != pod.Status.PodIP {
			return nil, fmt.Errorf("Pod %s/%s IP %q differs from NetworkInterface address %q", namespace, pod.Name, pod.Status.PodIP, address)
		}
		addresses = append(addresses, address.String())
	}
	return addresses, nil
}

func getNetworkInterface(namespace, name string) (*juneauv1alpha1.NetworkInterface, error) {
	out, err := kubectlOutput(repoRoot, "get", "networkinterface", "-n", namespace, name, "-o", "json")
	if err != nil {
		return nil, err
	}
	var nic juneauv1alpha1.NetworkInterface
	if err := json.Unmarshal([]byte(out), &nic); err != nil {
		return nil, fmt.Errorf("decode NetworkInterface %s/%s: %w", namespace, name, err)
	}
	return &nic, nil
}

func podReady(pod *corev1.Pod) bool {
	for i := range pod.Status.Conditions {
		condition := &pod.Status.Conditions[i]
		if condition.Type == corev1.PodReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

func hasReadyCondition(conditions []metav1.Condition, conditionType string, generation int64) bool {
	for i := range conditions {
		condition := &conditions[i]
		if condition.Type == conditionType {
			return condition.Status == metav1.ConditionTrue && condition.ObservedGeneration == generation
		}
	}
	return false
}

func subnetDNS(name string) string {
	var resolver string
	Eventually(func(g Gomega) {
		out, err := kubectlOutput(repoRoot, "get", "subnet", name, "-o", "json")
		g.Expect(err).NotTo(HaveOccurred())
		var subnet juneauv1alpha1.Subnet
		g.Expect(json.Unmarshal([]byte(out), &subnet)).To(Succeed())
		g.Expect(subnet.Status.ObservedGeneration).To(Equal(subnet.Generation))
		g.Expect(hasReadyCondition(subnet.Status.Conditions, juneauv1alpha1.SubnetStatusReady, subnet.Generation)).To(BeTrue())
		g.Expect(subnet.Status.DNS).NotTo(BeEmpty())
		resolver = subnet.Status.DNS
	}).Should(Succeed())
	return resolver
}

type dnsAAnswer struct {
	Name    string
	TTL     uint32
	Address string
}

func assertDNSAAnswers(namespace, pod, resolver, fqdn string, ttl uint32, expected []string) {
	Eventually(func(g Gomega) {
		out, err := kubectlOutput(repoRoot, "exec", "-n", namespace, pod, "--",
			"dig", "@"+resolver, "+noall", "+answer", "+time=3", "+tries=1", fqdn, "A")
		g.Expect(err).NotTo(HaveOccurred(), "dig output: %s", out)
		answers, err := parseDigAAnswers(out)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(answers).To(HaveLen(len(expected)))

		addresses := make([]string, len(answers))
		for i := range answers {
			g.Expect(strings.TrimSuffix(answers[i].Name, ".")).To(Equal(strings.TrimSuffix(fqdn, ".")))
			g.Expect(answers[i].TTL).To(Equal(ttl))
			addresses[i] = answers[i].Address
		}
		g.Expect(addresses).To(ConsistOf(expected))
	}).Should(Succeed())
}

func parseDigAAnswers(output string) ([]dnsAAnswer, error) {
	var answers []dnsAAnswer
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 5 || !strings.EqualFold(fields[2], "IN") || !strings.EqualFold(fields[3], "A") {
			return nil, fmt.Errorf("invalid dig A answer line %q", line)
		}
		ttl, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("parse TTL in dig answer line %q: %w", line, err)
		}
		address := net.ParseIP(fields[4])
		if address == nil || address.To4() == nil {
			return nil, fmt.Errorf("invalid IPv4 address in dig answer line %q", line)
		}
		answers = append(answers, dnsAAnswer{Name: fields[0], TTL: uint32(ttl), Address: address.String()})
	}
	return answers, nil
}

func assertAuthoritativeNXDomain(namespace, pod, resolver, fqdn string) {
	Eventually(func(g Gomega) {
		out, err := kubectlOutput(repoRoot, "exec", "-n", namespace, pod, "--",
			"dig", "@"+resolver, "+noall", "+comments", "+time=3", "+tries=1", fqdn, "A")
		g.Expect(err).NotTo(HaveOccurred(), "dig output: %s", out)
		rcode, flags, err := parseDigHeader(out)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(rcode).To(Equal("NXDOMAIN"))
		g.Expect(flags).To(HaveKey("aa"))
	}).Should(Succeed())
}

func parseDigHeader(output string) (string, map[string]struct{}, error) {
	var rcode string
	flags := map[string]struct{}{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "HEADER") {
			statusStart := strings.Index(line, "status: ")
			if statusStart < 0 {
				return "", nil, fmt.Errorf("dig header has no status: %q", line)
			}
			status := line[statusStart+len("status: "):]
			if comma := strings.Index(status, ","); comma >= 0 {
				status = status[:comma]
			}
			rcode = strings.TrimSpace(status)
		}
		if strings.HasPrefix(line, ";; flags:") {
			flagList := strings.TrimSpace(strings.TrimPrefix(line, ";; flags:"))
			if semicolon := strings.Index(flagList, ";"); semicolon >= 0 {
				flagList = flagList[:semicolon]
			}
			for _, flag := range strings.Fields(flagList) {
				flags[flag] = struct{}{}
			}
		}
	}
	if rcode == "" {
		return "", nil, fmt.Errorf("dig output has no response header: %q", output)
	}
	return rcode, flags, nil
}

func TestParseDigAAnswers(t *testing.T) {
	output := "backends.private.test. 30 IN A 10.220.0.7\nbackends.private.test. 30 IN A 10.220.0.5\n"
	answers, err := parseDigAAnswers(output)
	if err != nil {
		t.Fatalf("parseDigAAnswers returned an error: %v", err)
	}
	want := []dnsAAnswer{
		{Name: "backends.private.test.", TTL: 30, Address: "10.220.0.7"},
		{Name: "backends.private.test.", TTL: 30, Address: "10.220.0.5"},
	}
	if fmt.Sprint(answers) != fmt.Sprint(want) {
		t.Fatalf("parseDigAAnswers = %#v, want %#v", answers, want)
	}
}

func TestParseDigHeader(t *testing.T) {
	output := ";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1234\n;; flags: qr aa rd; QUERY: 1, ANSWER: 0\n"
	rcode, flags, err := parseDigHeader(output)
	if err != nil {
		t.Fatalf("parseDigHeader returned an error: %v", err)
	}
	if rcode != "NXDOMAIN" {
		t.Fatalf("parseDigHeader rcode = %q, want NXDOMAIN", rcode)
	}
	if _, ok := flags["aa"]; !ok {
		t.Fatalf("parseDigHeader flags = %v, want aa", flags)
	}
}
