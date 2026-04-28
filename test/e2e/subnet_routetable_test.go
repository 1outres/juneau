package e2e

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Subnet.spec.routeTable lets a Subnet override which RouteTable governs
// its Pods. The smoke covers the controller wiring only: Subnet becomes
// Ready, the referenced (non-main) RouteTable picks up the CONNECTED
// route and gets its own TableID. Functional verification through a
// real Pod traversing the alt-RT FIB is left to a future suite.
var _ = Describe("Subnet.spec.routeTable", Ordered, func() {
	It("propagates a Subnet's CONNECTED route to the alt RouteTable it references", func() {
		base := sanitizeName(uniqueAllocationBase())
		vpcName := fmt.Sprintf("vpc-rt-%s", base)
		altRTName := fmt.Sprintf("rt-alt-%s", base)
		subnetName := fmt.Sprintf("subnet-alt-%s", base)
		subnetCIDR := "10.180.0.0/24"

		manifest := fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: %s
---
apiVersion: juneau.loutres.me/v1alpha1
kind: RouteTable
metadata:
  name: %s
spec:
  vpc: %s
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: %s
spec:
  vpc: %s
  cidr: %s
  routeTable: %s
`, vpcName, altRTName, vpcName, subnetName, vpcName, subnetCIDR, altRTName)

		DeferCleanup(func() {
			runBestEffort(repoRoot, "kubectl", "delete", "subnet", subnetName, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "routetable", altRTName, "--ignore-not-found=true")
			// VpcReconciler auto-creates a main RT named after the Vpc;
			// remove it before the Vpc so the webhook does not block.
			runBestEffort(repoRoot, "kubectl", "delete", "vpc", vpcName, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "routetable", vpcName, "--ignore-not-found=true")
		})

		Expect(applyManifest(manifest)).To(Succeed())

		By("waiting for the alt-routed Subnet to become Ready")
		waitSubnetReady(subnetName)

		By("checking alt RouteTable allocates a non-zero, distinct TableID")
		Eventually(func(g Gomega) {
			altID, err := kubectlJSONPath(repoRoot, "{.status.tableID}", "get", "routetable", altRTName)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(strings.TrimSpace(altID)).NotTo(BeEmpty(), "alt RT missing tableID")
			g.Expect(strings.TrimSpace(altID)).NotTo(Equal("0"))

			mainID, err := kubectlJSONPath(repoRoot, "{.status.tableID}", "get", "routetable", vpcName)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(strings.TrimSpace(mainID)).NotTo(BeEmpty(), "main RT missing tableID")
			g.Expect(strings.TrimSpace(altID)).NotTo(Equal(strings.TrimSpace(mainID)),
				"alt RT %s and main RT %s share tableID, expected distinct allocations",
				altRTName, vpcName)
		}).Should(Succeed())

		By("checking the CONNECTED route for the Subnet appears on BOTH RouteTables in the Vpc")
		// CONNECTED routes follow Vpc semantics: every RouteTable in the
		// owning Vpc reaches every Subnet in that Vpc, regardless of
		// which RT is named on the Subnet's spec.routeTable.
		expectConnectedRoute := func(rtName string) {
			Eventually(func(g Gomega) {
				routes, err := kubectlJSONPath(repoRoot,
					fmt.Sprintf(`{.status.routes[?(@.dst=="%s")].via.type}`, subnetCIDR),
					"get", "routetable", rtName)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(strings.TrimSpace(routes)).To(Equal("connected"),
					"RouteTable %s missing CONNECTED route for %s", rtName, subnetCIDR)
			}).Should(Succeed())
		}
		expectConnectedRoute(altRTName)
		expectConnectedRoute(vpcName)
	})

	It("rejects deleting a RouteTable while a Subnet still references it via spec.routeTable", func() {
		base := sanitizeName(uniqueAllocationBase())
		vpcName := fmt.Sprintf("vpc-rt-del-%s", base)
		altRTName := fmt.Sprintf("rt-alt-del-%s", base)
		subnetName := fmt.Sprintf("subnet-alt-del-%s", base)
		subnetCIDR := "10.181.0.0/24"

		manifest := fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: %s
---
apiVersion: juneau.loutres.me/v1alpha1
kind: RouteTable
metadata:
  name: %s
spec:
  vpc: %s
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: %s
spec:
  vpc: %s
  cidr: %s
  routeTable: %s
`, vpcName, altRTName, vpcName, subnetName, vpcName, subnetCIDR, altRTName)

		DeferCleanup(func() {
			runBestEffort(repoRoot, "kubectl", "delete", "subnet", subnetName, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "routetable", altRTName, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "vpc", vpcName, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "routetable", vpcName, "--ignore-not-found=true")
		})

		Expect(applyManifest(manifest)).To(Succeed())
		waitSubnetReady(subnetName)

		// kubectlOutput drops stderr from the returned error, so only
		// assert that the deletion was rejected here. The exact webhook
		// message ("Subnet ... references this RouteTable...") is
		// already covered by the routetable webhook unit tests.
		out, err := kubectlOutput(repoRoot, "delete", "routetable", altRTName)
		Expect(err).To(HaveOccurred(), "delete should be rejected, got output %q", out)

		// Confirm the RouteTable is still present (the rejection should
		// have prevented any state change).
		_, err = kubectlJSONPath(repoRoot, "{.metadata.name}", "get", "routetable", altRTName)
		Expect(err).NotTo(HaveOccurred(), "RouteTable should still exist after rejected delete")
	})
})
