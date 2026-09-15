package controller

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("DNSRecord controller", func() {
	It("unions, deduplicates and numerically sorts fixed, named, endpoint and three selected Pod addresses", func() {
		vpcName := createControllerVpcWithEndpointPool(uniqueEndpointPoolCIDR())
		subnet := createControllerSubnet(vpcName, uniqueTestName("subnet"), uniqueSubnetCIDR())
		namespace := createDNSControllerNamespace()
		addresses := []string{"10.44.0.4", "10.44.0.2", "10.44.0.3"}
		interfaces := make([]*juneauv1alpha1.NetworkInterface, 0, len(addresses))
		for i, address := range addresses {
			pod := createDNSPod(namespace, fmt.Sprintf("selected-%d", i), map[string]string{"dns-test": "selected"}, true)
			interfaces = append(interfaces, createDNSNetworkInterface(pod, "eth0", subnet.Name, address+"/24"))
		}

		backendNamespace, serviceName := createVpcEndpointBackend("")
		endpointName := createVpcEndpoint(vpcName, backendNamespace, serviceName)
		zoneName := createControllerDNSZone(vpcName, "mixed.example.com")
		record := newControllerDNSRecord(zoneName, "api", []juneauv1alpha1.DNSRecordSource{
			{IP: dnsStringPointer("192.0.2.10")},
			{IP: dnsStringPointer("10.44.0.2")},
			{NetworkInterface: &juneauv1alpha1.DNSNetworkInterfaceSource{Namespace: namespace, Name: interfaces[0].Name}},
			{VpcEndpoint: &juneauv1alpha1.DNSVpcEndpointSource{Name: endpointName}},
			{PodSelector: &juneauv1alpha1.DNSPodSelectorSource{
				Namespace: namespace,
				Interface: "eth0",
				Selector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key: "dns-test", Operator: metav1.LabelSelectorOpIn, Values: []string{"selected"},
				}}},
			}},
		})
		Expect(k8sClient.Create(context.Background(), record)).To(Succeed())

		Eventually(func(g Gomega) {
			stored := getControllerDNSRecord(record.Name)
			condition := meta.FindStatusCondition(stored.Status.Conditions, juneauv1alpha1.DNSRecordConditionReady)
			g.Expect(condition).NotTo(BeNil())
			g.Expect(condition.Status).To(Equal(metav1.ConditionTrue))
			g.Expect(condition.ObservedGeneration).To(Equal(stored.Generation))
			g.Expect(stored.Status.ObservedGeneration).To(Equal(stored.Generation))
			g.Expect(stored.Status.Addresses).To(HaveLen(5))
			g.Expect(stored.Status.Addresses[:3]).To(Equal([]string{"10.44.0.2", "10.44.0.3", "10.44.0.4"}))
			g.Expect(stored.Status.Addresses[4]).To(Equal("192.0.2.10"))
		}).Should(Succeed())
	})

	It("filters Pod and interface readiness, UID, interface, deletion and Vpc, then reacts to Pod and NIC changes", func() {
		vpcName := createControllerVpc()
		foreignVpc := createControllerVpc()
		subnet := createControllerSubnet(vpcName, uniqueTestName("subnet"), uniqueSubnetCIDR())
		foreignSubnet := createControllerSubnet(foreignVpc, uniqueTestName("subnet"), uniqueSubnetCIDR())
		namespace := createDNSControllerNamespace()
		labels := map[string]string{"dns-test": "filter"}

		validPod := createDNSPod(namespace, "valid", labels, true)
		validNIC := createDNSNetworkInterface(validPod, "eth0", subnet.Name, "10.45.0.2/24")
		unreadyPod := createDNSPod(namespace, "unready", labels, false)
		createDNSNetworkInterface(unreadyPod, "eth0", subnet.Name, "10.45.0.3/24")
		wrongUIDPod := createDNSPod(namespace, "wrong-uid", labels, true)
		createDNSNetworkInterfaceForUID(wrongUIDPod, uniqueTestName("nic"), "another-uid", "eth0", subnet.Name, "10.45.0.4/24")
		wrongInterfacePod := createDNSPod(namespace, "wrong-interface", labels, true)
		createDNSNetworkInterface(wrongInterfacePod, "net1", subnet.Name, "10.45.0.5/24")
		foreignPod := createDNSPod(namespace, "foreign", labels, true)
		createDNSNetworkInterface(foreignPod, "eth0", foreignSubnet.Name, "10.45.0.6/24")

		zoneName := createControllerDNSZone(vpcName, "filter.example.com")
		record := newControllerDNSRecord(zoneName, "pods", []juneauv1alpha1.DNSRecordSource{{
			PodSelector: &juneauv1alpha1.DNSPodSelectorSource{
				Namespace: namespace,
				Interface: "eth0",
				Selector:  metav1.LabelSelector{MatchLabels: labels},
			},
		}})
		Expect(k8sClient.Create(context.Background(), record)).To(Succeed())
		expectDNSRecordReadyWithAddresses(record.Name, "10.45.0.2")

		setDNSPodReady(validPod, false)
		expectDNSRecordReadyWithAddresses(record.Name)
		setDNSPodReady(validPod, true)
		expectDNSRecordReadyWithAddresses(record.Name, "10.45.0.2")

		Expect(k8sClient.Delete(context.Background(), validNIC)).To(Succeed())
		expectDNSRecordReadyWithAddresses(record.Name)
	})

	It("re-resolves a Pod selector when a matching label is added and removed", func() {
		vpcName := createControllerVpc()
		subnet := createControllerSubnet(vpcName, uniqueTestName("subnet"), uniqueSubnetCIDR())
		namespace := createDNSControllerNamespace()
		pod := createDNSPod(namespace, "label-watch", map[string]string{"other": "label"}, true)
		createDNSNetworkInterface(pod, "eth0", subnet.Name, "10.45.1.2/24")
		zoneName := createControllerDNSZone(vpcName, "label-watch.example.com")
		record := newControllerDNSRecord(zoneName, "pods", []juneauv1alpha1.DNSRecordSource{{
			PodSelector: &juneauv1alpha1.DNSPodSelectorSource{
				Namespace: namespace,
				Interface: "eth0",
				Selector:  metav1.LabelSelector{MatchLabels: map[string]string{"dns-test": "label-watch"}},
			},
		}})
		Expect(k8sClient.Create(context.Background(), record)).To(Succeed())
		expectDNSRecordReadyWithAddresses(record.Name)

		Eventually(func() error {
			var stored corev1.Pod
			if err := k8sClient.Get(context.Background(), client.ObjectKeyFromObject(pod), &stored); err != nil {
				return err
			}
			stored.Labels["dns-test"] = "label-watch"
			return k8sClient.Update(context.Background(), &stored)
		}).Should(Succeed())
		expectDNSRecordReadyWithAddresses(record.Name, "10.45.1.2")

		Eventually(func() error {
			var stored corev1.Pod
			if err := k8sClient.Get(context.Background(), client.ObjectKeyFromObject(pod), &stored); err != nil {
				return err
			}
			delete(stored.Labels, "dns-test")
			return k8sClient.Update(context.Background(), &stored)
		}).Should(Succeed())
		expectDNSRecordReadyWithAddresses(record.Name)
	})

	It("publishes no partial addresses for a missing named source and recovers when it appears", func() {
		vpcName := createControllerVpc()
		subnet := createControllerSubnet(vpcName, uniqueTestName("subnet"), uniqueSubnetCIDR())
		namespace := createDNSControllerNamespace()
		missingName := uniqueTestName("nic")
		zoneName := createControllerDNSZone(vpcName, "recovery.example.com")
		record := newControllerDNSRecord(zoneName, "api", []juneauv1alpha1.DNSRecordSource{
			{IP: dnsStringPointer("192.0.2.20")},
			{NetworkInterface: &juneauv1alpha1.DNSNetworkInterfaceSource{Namespace: namespace, Name: missingName}},
		})
		Expect(k8sClient.Create(context.Background(), record)).To(Succeed())

		Eventually(func(g Gomega) {
			stored := getControllerDNSRecord(record.Name)
			condition := meta.FindStatusCondition(stored.Status.Conditions, juneauv1alpha1.DNSRecordConditionReady)
			g.Expect(condition).NotTo(BeNil())
			g.Expect(condition.Status).To(Equal(metav1.ConditionFalse))
			g.Expect(condition.Reason).To(Equal(dnsRecordReasonSourceNotFound))
			g.Expect(stored.Status.Addresses).To(BeEmpty())
		}).Should(Succeed())

		pod := createDNSPod(namespace, "recovered", map[string]string{"dns-test": "recovered"}, true)
		createDNSNetworkInterfaceWithName(pod, missingName, "eth0", subnet.Name, "10.46.0.2/24")
		expectDNSRecordReadyWithAddresses(record.Name, "10.46.0.2", "192.0.2.20")
	})

	It("re-evaluates a named interface when its Subnet changes Vpc", func() {
		vpcName := createControllerVpc()
		foreignVpc := createControllerVpc()
		subnet := createControllerSubnet(vpcName, uniqueTestName("subnet"), uniqueSubnetCIDR())
		namespace := createDNSControllerNamespace()
		pod := createDNSPod(namespace, "network-watch", map[string]string{"dns-test": "network-watch"}, true)
		nic := createDNSNetworkInterface(pod, "eth0", subnet.Name, "10.49.0.2/24")
		zoneName := createControllerDNSZone(vpcName, "network-watch.example.com")
		record := newControllerDNSRecord(zoneName, "api", []juneauv1alpha1.DNSRecordSource{{
			NetworkInterface: &juneauv1alpha1.DNSNetworkInterfaceSource{Namespace: namespace, Name: nic.Name},
		}})
		Expect(k8sClient.Create(context.Background(), record)).To(Succeed())
		expectDNSRecordReadyWithAddresses(record.Name, "10.49.0.2")

		Eventually(func() error {
			var stored juneauv1alpha1.Subnet
			if err := k8sClient.Get(context.Background(), client.ObjectKey{Name: subnet.Name}, &stored); err != nil {
				return err
			}
			stored.Spec.Vpc = foreignVpc
			return k8sClient.Update(context.Background(), &stored)
		}).Should(Succeed())
		Eventually(func(g Gomega) {
			stored := getControllerDNSRecord(record.Name)
			condition := meta.FindStatusCondition(stored.Status.Conditions, juneauv1alpha1.DNSRecordConditionReady)
			g.Expect(condition).NotTo(BeNil())
			g.Expect(condition.Status).To(Equal(metav1.ConditionFalse))
			g.Expect(condition.Reason).To(Equal(dnsRecordReasonSourceVpcMismatch))
			g.Expect(stored.Status.Addresses).To(BeEmpty())
		}).Should(Succeed())
	})

	It("marks duplicate records not Ready and recovers the survivor after deletion", func() {
		zoneName := createControllerDNSZone(createControllerVpc(), "record-race.example.com")
		first := newControllerDNSRecord(zoneName, "api", []juneauv1alpha1.DNSRecordSource{{IP: dnsStringPointer("192.0.2.30")}})
		second := newControllerDNSRecord(zoneName, "api", []juneauv1alpha1.DNSRecordSource{{IP: dnsStringPointer("192.0.2.31")}})
		Expect(k8sClient.Create(context.Background(), first)).To(Succeed())
		Expect(k8sClient.Create(context.Background(), second)).To(Succeed())

		for _, name := range []string{first.Name, second.Name} {
			Eventually(func(g Gomega) {
				stored := getControllerDNSRecord(name)
				condition := meta.FindStatusCondition(stored.Status.Conditions, juneauv1alpha1.DNSRecordConditionReady)
				g.Expect(condition).NotTo(BeNil())
				g.Expect(condition.Status).To(Equal(metav1.ConditionFalse))
				g.Expect(condition.Reason).To(Equal(dnsRecordReasonDuplicate))
				g.Expect(stored.Status.Addresses).To(BeEmpty())
			}).Should(Succeed())
		}

		Expect(k8sClient.Delete(context.Background(), second)).To(Succeed())
		expectDNSRecordReadyWithAddresses(first.Name, "192.0.2.30")
	})

	It("excludes a current ready interface whose Pod UID does not match", func() {
		vpc := &juneauv1alpha1.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "uid-vpc"}}
		zone := readyDNSZone("uid-zone", vpc.Name, "uid.example.com")
		subnet := &juneauv1alpha1.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "uid-subnet"}, Spec: juneauv1alpha1.SubnetSpec{Vpc: vpc.Name, CIDR: "10.52.0.0/16"}}
		pod := readyDNSPod("default", "uid-pod", "wanted-uid", map[string]string{"app": "uid-test"})
		nic := readyDNSNetworkInterface("default", "uid-nic", "different-uid", "eth0", subnet.Name, "10.52.0.2/16")
		record := newControllerDNSRecord(zone.Name, "uid", []juneauv1alpha1.DNSRecordSource{{PodSelector: &juneauv1alpha1.DNSPodSelectorSource{
			Namespace: "default", Interface: "eth0", Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "uid-test"}},
		}}})
		record.Generation = 1
		reconciler := &DNSRecordReconciler{Client: newDNSFakeClient(vpc, zone, subnet, pod, nic, record), Scheme: scheme.Scheme}

		desired, err := reconciler.buildStatus(context.Background(), record)
		Expect(err).NotTo(HaveOccurred())
		Expect(desired.Ready.Status).To(Equal(metav1.ConditionTrue))
		Expect(desired.Addresses).To(BeEmpty())
	})

	It("loads each Pod selector namespace once per resolution", func() {
		vpc := &juneauv1alpha1.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "snapshot-vpc"}}
		zone := readyDNSZone("snapshot-zone", vpc.Name, "snapshot.example.com")
		subnet := &juneauv1alpha1.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "snapshot-subnet"}, Spec: juneauv1alpha1.SubnetSpec{Vpc: vpc.Name, CIDR: "10.50.0.0/16"}}
		pod := readyDNSPod("default", "snapshot-pod", "snapshot-uid", map[string]string{"app": "api", "tier": "backend"})
		nic := readyDNSNetworkInterface("default", "snapshot-nic", string(pod.UID), "eth0", subnet.Name, "10.50.0.2/16")
		record := newControllerDNSRecord(zone.Name, "snapshot", []juneauv1alpha1.DNSRecordSource{
			{PodSelector: &juneauv1alpha1.DNSPodSelectorSource{Namespace: "default", Interface: "eth0", Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}}}},
			{PodSelector: &juneauv1alpha1.DNSPodSelectorSource{Namespace: "default", Interface: "eth0", Selector: metav1.LabelSelector{MatchLabels: map[string]string{"tier": "backend"}}}},
		})
		record.Generation = 1
		countingClient := &dnsCountingClient{Client: newDNSFakeClient(vpc, zone, subnet, pod, nic, record)}
		reconciler := &DNSRecordReconciler{Client: countingClient, Scheme: scheme.Scheme}

		desired, err := reconciler.buildStatus(context.Background(), record)
		Expect(err).NotTo(HaveOccurred())
		Expect(desired.Addresses).To(Equal([]string{"10.50.0.2"}))
		Expect(countingClient.podLists).To(Equal(1))
		Expect(countingClient.networkInterfaceLists).To(Equal(1))
	})

	It("does not publish from stale DNSZone, NetworkInterface or VpcEndpoint status", func() {
		vpc := &juneauv1alpha1.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "stale-vpc"}}

		staleZone := readyDNSZone("stale-zone", vpc.Name, "stale.example.com")
		staleZone.Status.ObservedGeneration = 0
		fixedRecord := newControllerDNSRecord(staleZone.Name, "fixed", []juneauv1alpha1.DNSRecordSource{{IP: dnsStringPointer("192.0.2.50")}})
		fixedRecord.Generation = 1
		desired, err := (&DNSRecordReconciler{Client: newDNSFakeClient(vpc, staleZone, fixedRecord), Scheme: scheme.Scheme}).buildStatus(context.Background(), fixedRecord)
		Expect(err).NotTo(HaveOccurred())
		Expect(desired.Ready.Status).To(Equal(metav1.ConditionFalse))
		Expect(desired.Ready.Reason).To(Equal(dnsRecordReasonZoneNotReady))
		Expect(desired.Addresses).To(BeEmpty())

		zone := readyDNSZone("current-zone", vpc.Name, "current.example.com")
		subnet := &juneauv1alpha1.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "stale-subnet"}, Spec: juneauv1alpha1.SubnetSpec{Vpc: vpc.Name, CIDR: "10.51.0.0/16"}}
		staleNIC := readyDNSNetworkInterface("default", "stale-nic", "uid", "eth0", subnet.Name, "10.51.0.2/16")
		staleNIC.Generation = 2
		nicRecord := newControllerDNSRecord(zone.Name, "nic", []juneauv1alpha1.DNSRecordSource{{NetworkInterface: &juneauv1alpha1.DNSNetworkInterfaceSource{Namespace: staleNIC.Namespace, Name: staleNIC.Name}}})
		nicRecord.Generation = 1
		desired, err = (&DNSRecordReconciler{Client: newDNSFakeClient(vpc, zone, subnet, staleNIC, nicRecord), Scheme: scheme.Scheme}).buildStatus(context.Background(), nicRecord)
		Expect(err).NotTo(HaveOccurred())
		Expect(desired.Ready.Status).To(Equal(metav1.ConditionTrue))
		Expect(desired.Addresses).To(BeEmpty())

		staleEndpoint := readyDNSVpcEndpoint("stale-endpoint", vpc.Name, "192.0.2.51")
		staleEndpoint.Generation = 2
		endpointRecord := newControllerDNSRecord(zone.Name, "endpoint", []juneauv1alpha1.DNSRecordSource{{VpcEndpoint: &juneauv1alpha1.DNSVpcEndpointSource{Name: staleEndpoint.Name}}})
		endpointRecord.Generation = 1
		desired, err = (&DNSRecordReconciler{Client: newDNSFakeClient(vpc, zone, staleEndpoint, endpointRecord), Scheme: scheme.Scheme}).buildStatus(context.Background(), endpointRecord)
		Expect(err).NotTo(HaveOccurred())
		Expect(desired.Ready.Status).To(Equal(metav1.ConditionTrue))
		Expect(desired.Addresses).To(BeEmpty())
	})

	It("uses the two VpcEndpoint gates instead of overall Ready and rejects a foreign endpoint", func() {
		vpc := &juneauv1alpha1.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "endpoint-vpc"}}
		zone := readyDNSZone("endpoint-zone", vpc.Name, "endpoint.example.com")
		endpoint := &juneauv1alpha1.VpcEndpoint{
			ObjectMeta: metav1.ObjectMeta{Name: "endpoint", Generation: 1},
			Spec:       juneauv1alpha1.VpcEndpointSpec{Vpc: vpc.Name, Service: juneauv1alpha1.VpcEndpointServiceReference{Namespace: "default", Name: "service"}},
			Status: juneauv1alpha1.VpcEndpointStatus{ObservedGeneration: 1, Address: "192.0.2.40", Conditions: []metav1.Condition{
				{Type: juneauv1alpha1.VpcEndpointConditionAddressAllocated, Status: metav1.ConditionTrue, Reason: "Allocated", Message: "allocated", ObservedGeneration: 1},
				{Type: juneauv1alpha1.VpcEndpointConditionServiceAccepted, Status: metav1.ConditionFalse, Reason: "Pending", Message: "pending", ObservedGeneration: 1},
				{Type: juneauv1alpha1.VpcEndpointConditionReady, Status: metav1.ConditionFalse, Reason: "BackendUnavailable", Message: "unavailable", ObservedGeneration: 1},
			}},
		}
		record := newControllerDNSRecord(zone.Name, "endpoint", []juneauv1alpha1.DNSRecordSource{{VpcEndpoint: &juneauv1alpha1.DNSVpcEndpointSource{Name: endpoint.Name}}})
		record.Generation = 1
		fakeClient := newDNSFakeClient(vpc, zone, endpoint, record)
		reconciler := &DNSRecordReconciler{Client: fakeClient, Scheme: scheme.Scheme}

		desired, err := reconciler.buildStatus(context.Background(), record)
		Expect(err).NotTo(HaveOccurred())
		Expect(desired.Ready.Status).To(Equal(metav1.ConditionTrue))
		Expect(desired.Addresses).To(BeEmpty())

		var stored juneauv1alpha1.VpcEndpoint
		Expect(fakeClient.Get(context.Background(), client.ObjectKey{Name: endpoint.Name}, &stored)).To(Succeed())
		meta.SetStatusCondition(&stored.Status.Conditions, metav1.Condition{Type: juneauv1alpha1.VpcEndpointConditionServiceAccepted,
			Status: metav1.ConditionTrue, Reason: "Accepted", Message: "accepted", ObservedGeneration: 1})
		Expect(fakeClient.Update(context.Background(), &stored)).To(Succeed())
		desired, err = reconciler.buildStatus(context.Background(), record)
		Expect(err).NotTo(HaveOccurred())
		Expect(desired.Ready.Status).To(Equal(metav1.ConditionTrue))
		Expect(desired.Addresses).To(Equal([]string{"192.0.2.40"}))

		Expect(fakeClient.Get(context.Background(), client.ObjectKey{Name: endpoint.Name}, &stored)).To(Succeed())
		stored.Spec.Vpc = "foreign-vpc"
		Expect(fakeClient.Update(context.Background(), &stored)).To(Succeed())
		desired, err = reconciler.buildStatus(context.Background(), record)
		Expect(err).NotTo(HaveOccurred())
		Expect(desired.Ready.Status).To(Equal(metav1.ConditionFalse))
		Expect(desired.Ready.Reason).To(Equal(dnsRecordReasonSourceVpcMismatch))
		Expect(desired.Addresses).To(BeEmpty())
	})

	It("treats an unready named interface as an empty result and rejects it in a foreign Vpc", func() {
		vpc := &juneauv1alpha1.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "named-vpc"}}
		zone := readyDNSZone("named-zone", vpc.Name, "named.example.com")
		subnet := &juneauv1alpha1.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "named-subnet"}, Spec: juneauv1alpha1.SubnetSpec{Vpc: vpc.Name, CIDR: "10.48.0.0/16"}}
		nic := &juneauv1alpha1.NetworkInterface{ObjectMeta: metav1.ObjectMeta{Name: "named-nic", Namespace: "default", Generation: 1},
			Spec: juneauv1alpha1.NetworkInterfaceSpec{PodRef: juneauv1alpha1.NetworkInterfacePodReference{Name: "pod", UID: "uid", Interface: "eth0"}, NodeName: "node", Subnet: subnet.Name}}
		record := newControllerDNSRecord(zone.Name, "named", []juneauv1alpha1.DNSRecordSource{{NetworkInterface: &juneauv1alpha1.DNSNetworkInterfaceSource{Namespace: nic.Namespace, Name: nic.Name}}})
		record.Generation = 1
		fakeClient := newDNSFakeClient(vpc, zone, subnet, nic, record)
		reconciler := &DNSRecordReconciler{Client: fakeClient, Scheme: scheme.Scheme}

		desired, err := reconciler.buildStatus(context.Background(), record)
		Expect(err).NotTo(HaveOccurred())
		Expect(desired.Ready.Status).To(Equal(metav1.ConditionTrue))
		Expect(desired.Addresses).To(BeEmpty())

		var storedSubnet juneauv1alpha1.Subnet
		Expect(fakeClient.Get(context.Background(), client.ObjectKey{Name: subnet.Name}, &storedSubnet)).To(Succeed())
		storedSubnet.Spec.Vpc = "foreign-vpc"
		Expect(fakeClient.Update(context.Background(), &storedSubnet)).To(Succeed())
		desired, err = reconciler.buildStatus(context.Background(), record)
		Expect(err).NotTo(HaveOccurred())
		Expect(desired.Ready.Reason).To(Equal(dnsRecordReasonSourceVpcMismatch))
		Expect(desired.Addresses).To(BeEmpty())
	})

	It("rejects malformed resolved addresses and more than 100 resolved addresses without truncating", func() {
		vpc := &juneauv1alpha1.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "vpc"}}
		zone := &juneauv1alpha1.DNSZone{
			ObjectMeta: metav1.ObjectMeta{Name: "zone", Generation: 1},
			Spec:       juneauv1alpha1.DNSZoneSpec{Vpc: vpc.Name, Domain: "overflow.example.com"},
			Status: juneauv1alpha1.DNSZoneStatus{
				ObservedGeneration: 1,
				Conditions: []metav1.Condition{{Type: juneauv1alpha1.DNSZoneConditionReady, Status: metav1.ConditionTrue,
					Reason: "Ready", Message: "ready", ObservedGeneration: 1}},
			},
		}
		subnet := &juneauv1alpha1.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "subnet"}, Spec: juneauv1alpha1.SubnetSpec{Vpc: vpc.Name, CIDR: "10.47.0.0/16"}}
		record := newControllerDNSRecord(zone.Name, "many", []juneauv1alpha1.DNSRecordSource{
			{PodSelector: &juneauv1alpha1.DNSPodSelectorSource{
				Namespace: "default", Interface: "eth0", Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "many"}},
			}},
			{NetworkInterface: &juneauv1alpha1.DNSNetworkInterfaceSource{Namespace: "default", Name: "must-not-be-read-after-overflow"}},
		})
		record.Generation = 1

		objects := []client.Object{vpc, zone, subnet, record}
		for i := 0; i < 101; i++ {
			uid := types.UID(fmt.Sprintf("uid-%d", i))
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("pod-%d", i), Namespace: "default", UID: uid, Labels: map[string]string{"app": "many"}},
				Status: corev1.PodStatus{Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
			nic := &juneauv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("nic-%d", i), Namespace: "default", Generation: 1},
				Spec: juneauv1alpha1.NetworkInterfaceSpec{PodRef: juneauv1alpha1.NetworkInterfacePodReference{
					Name: pod.Name, UID: string(uid), Interface: "eth0"}, NodeName: "node", Subnet: subnet.Name},
				Status: juneauv1alpha1.NetworkInterfaceStatus{ObservedGeneration: 1, Address: fmt.Sprintf("10.47.0.%d/16", i+1),
					Conditions: []metav1.Condition{{Type: juneauv1alpha1.NetworkInterfaceStatusReady, Status: metav1.ConditionTrue,
						Reason: "Ready", Message: "ready", ObservedGeneration: 1, LastTransitionTime: metav1.Now()}}},
			}
			objects = append(objects, pod, nic)
		}
		fakeClient := newDNSFakeClient(objects...)
		reconciler := &DNSRecordReconciler{Client: fakeClient, Scheme: scheme.Scheme}
		desired, err := reconciler.buildStatus(context.Background(), record)
		Expect(err).NotTo(HaveOccurred())
		Expect(desired.Ready.Status).To(Equal(metav1.ConditionFalse))
		Expect(desired.Ready.Reason).To(Equal(dnsRecordReasonTooManyAddresses))
		Expect(desired.Addresses).To(BeEmpty())

		var malformed juneauv1alpha1.NetworkInterface
		Expect(fakeClient.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "nic-0"}, &malformed)).To(Succeed())
		malformed.Status.Address = "not-a-cidr"
		Expect(fakeClient.Update(context.Background(), &malformed)).To(Succeed())
		record.Spec.Sources = []juneauv1alpha1.DNSRecordSource{{NetworkInterface: &juneauv1alpha1.DNSNetworkInterfaceSource{Namespace: "default", Name: malformed.Name}}}
		desired, err = reconciler.buildStatus(context.Background(), record)
		Expect(err).NotTo(HaveOccurred())
		Expect(desired.Ready.Reason).To(Equal(dnsRecordReasonInvalidAddress))
		Expect(desired.Addresses).To(BeEmpty())
	})
})

func newControllerDNSRecord(zone, name string, sources []juneauv1alpha1.DNSRecordSource) *juneauv1alpha1.DNSRecord {
	ttl := int32(30)
	return &juneauv1alpha1.DNSRecord{
		ObjectMeta: metav1.ObjectMeta{Name: uniqueTestName("record")},
		Spec:       juneauv1alpha1.DNSRecordSpec{Zone: zone, Name: name, Type: juneauv1alpha1.DNSRecordTypeA, TTL: &ttl, Sources: sources},
	}
}

func dnsStringPointer(value string) *string { return &value }

func getControllerDNSRecord(name string) *juneauv1alpha1.DNSRecord {
	var record juneauv1alpha1.DNSRecord
	Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &record)).To(Succeed())
	return &record
}

func expectDNSRecordReadyWithAddresses(name string, addresses ...string) {
	Eventually(func(g Gomega) {
		record := getControllerDNSRecord(name)
		condition := meta.FindStatusCondition(record.Status.Conditions, juneauv1alpha1.DNSRecordConditionReady)
		g.Expect(condition).NotTo(BeNil())
		g.Expect(condition.Status).To(Equal(metav1.ConditionTrue), condition.Message)
		if len(addresses) == 0 {
			g.Expect(record.Status.Addresses).To(BeEmpty())
		} else {
			g.Expect(record.Status.Addresses).To(Equal(addresses))
		}
	}).Should(Succeed())
}

func createDNSControllerNamespace() string {
	name := uniqueTestName("dns")
	Expect(k8sClient.Create(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}})).To(Succeed())
	return name
}

func createDNSPod(namespace, suffix string, labels map[string]string, ready bool) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: uniqueTestName(suffix), Namespace: namespace, Labels: labels},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "test", Image: "test"}}},
	}
	Expect(k8sClient.Create(context.Background(), pod)).To(Succeed())
	setDNSPodReady(pod, ready)
	return pod
}

func setDNSPodReady(pod *corev1.Pod, ready bool) {
	var stored corev1.Pod
	Expect(k8sClient.Get(context.Background(), client.ObjectKeyFromObject(pod), &stored)).To(Succeed())
	status := corev1.ConditionFalse
	if ready {
		status = corev1.ConditionTrue
	}
	stored.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: status}}
	Expect(k8sClient.Status().Update(context.Background(), &stored)).To(Succeed())
	*pod = stored
}

func createDNSNetworkInterface(pod *corev1.Pod, interfaceName, subnetName, address string) *juneauv1alpha1.NetworkInterface {
	return createDNSNetworkInterfaceWithName(pod, uniqueTestName("nic"), interfaceName, subnetName, address)
}

func readyDNSZone(name, vpc, domain string) *juneauv1alpha1.DNSZone {
	return &juneauv1alpha1.DNSZone{
		ObjectMeta: metav1.ObjectMeta{Name: name, Generation: 1},
		Spec:       juneauv1alpha1.DNSZoneSpec{Vpc: vpc, Domain: domain},
		Status: juneauv1alpha1.DNSZoneStatus{ObservedGeneration: 1, Conditions: []metav1.Condition{{
			Type: juneauv1alpha1.DNSZoneConditionReady, Status: metav1.ConditionTrue, Reason: "Ready", Message: "ready", ObservedGeneration: 1,
		}}},
	}
}

func readyDNSPod(namespace, name, uid string, podLabels map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, UID: types.UID(uid), Labels: podLabels},
		Status:     corev1.PodStatus{Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
	}
}

func readyDNSNetworkInterface(namespace, name, uid, interfaceName, subnetName, address string) *juneauv1alpha1.NetworkInterface {
	return &juneauv1alpha1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, Generation: 1},
		Spec: juneauv1alpha1.NetworkInterfaceSpec{
			PodRef:   juneauv1alpha1.NetworkInterfacePodReference{Name: "pod", UID: uid, Interface: interfaceName},
			NodeName: "node", Subnet: subnetName,
		},
		Status: juneauv1alpha1.NetworkInterfaceStatus{
			ObservedGeneration: 1,
			Address:            address,
			Conditions: []metav1.Condition{{Type: juneauv1alpha1.NetworkInterfaceStatusReady, Status: metav1.ConditionTrue,
				Reason: "Ready", Message: "ready", ObservedGeneration: 1}},
		},
	}
}

func readyDNSVpcEndpoint(name, vpc, address string) *juneauv1alpha1.VpcEndpoint {
	return &juneauv1alpha1.VpcEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: name, Generation: 1},
		Spec:       juneauv1alpha1.VpcEndpointSpec{Vpc: vpc, Service: juneauv1alpha1.VpcEndpointServiceReference{Namespace: "default", Name: "service"}},
		Status: juneauv1alpha1.VpcEndpointStatus{ObservedGeneration: 1, Address: address, Conditions: []metav1.Condition{
			{Type: juneauv1alpha1.VpcEndpointConditionAddressAllocated, Status: metav1.ConditionTrue, Reason: "Allocated", Message: "allocated", ObservedGeneration: 1},
			{Type: juneauv1alpha1.VpcEndpointConditionServiceAccepted, Status: metav1.ConditionTrue, Reason: "Accepted", Message: "accepted", ObservedGeneration: 1},
		}},
	}
}

func newDNSFakeClient(objects ...client.Object) client.Client {
	return fake.NewClientBuilder().WithScheme(scheme.Scheme).
		WithIndex(&juneauv1alpha1.DNSRecord{}, dnsRecordZoneIndex, func(obj client.Object) []string {
			return []string{obj.(*juneauv1alpha1.DNSRecord).Spec.Zone}
		}).
		WithObjects(objects...).
		Build()
}

type dnsCountingClient struct {
	client.Client
	podLists              int
	networkInterfaceLists int
}

func (c *dnsCountingClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	switch list.(type) {
	case *corev1.PodList:
		c.podLists++
	case *juneauv1alpha1.NetworkInterfaceList:
		c.networkInterfaceLists++
	}
	return c.Client.List(ctx, list, opts...)
}

func createDNSNetworkInterfaceWithName(pod *corev1.Pod, name, interfaceName, subnetName, address string) *juneauv1alpha1.NetworkInterface {
	return createDNSNetworkInterfaceForUID(pod, name, string(pod.UID), interfaceName, subnetName, address)
}

func createDNSNetworkInterfaceForUID(pod *corev1.Pod, name, uid, interfaceName, subnetName, address string) *juneauv1alpha1.NetworkInterface {
	nic := &juneauv1alpha1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: pod.Namespace},
		Spec: juneauv1alpha1.NetworkInterfaceSpec{
			PodRef:   juneauv1alpha1.NetworkInterfacePodReference{Name: pod.Name, UID: uid, Interface: interfaceName},
			NodeName: "node", Subnet: subnetName,
		},
	}
	Expect(k8sClient.Create(context.Background(), nic)).To(Succeed())
	nic.Status.ObservedGeneration = nic.Generation
	nic.Status.Address = address
	nic.Status.Conditions = []metav1.Condition{{Type: juneauv1alpha1.NetworkInterfaceStatusReady, Status: metav1.ConditionTrue, Reason: "Ready", Message: "ready", ObservedGeneration: nic.Generation, LastTransitionTime: metav1.Now()}}
	Expect(k8sClient.Status().Update(context.Background(), nic)).To(Succeed())
	return nic
}
