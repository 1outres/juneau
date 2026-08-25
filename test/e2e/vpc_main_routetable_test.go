package e2e

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Vpc main RouteTable declared next to its Vpc", func() {
	It("takes the routes of a server-side apply that runs after the controller created it", func() {
		vpcName := fmt.Sprintf("vpc-main-rt-late-%s", sanitizeName(uniqueAllocationBase()))
		declaredRoutes := []route{internetGatewayRoute("0.0.0.0/0")}
		DeferCleanup(cleanupVpcWithMainRouteTable, vpcName)

		By("creating the Vpc on its own")
		Expect(applyManifestServerSide(vpcManifest(vpcName))).To(Succeed())

		By("waiting for the controller to create the main RouteTable")
		Expect(waitVpcMainRouteTable(vpcName)).To(Equal(vpcName))

		By("applying the Vpc and its main RouteTable as a single manifest")
		manifest, err := vpcWithMainRouteTableManifest(vpcName, declaredRoutes...)
		Expect(err).NotTo(HaveOccurred())
		Expect(applyManifestServerSide(manifest)).To(Succeed())

		By("checking the declared routes landed in spec.routes")
		obj, err := getRouteTableObject(vpcName)
		Expect(err).NotTo(HaveOccurred())
		Expect(obj.Spec.Vpc).To(Equal(vpcName))
		Expect(obj.Spec.Routes).To(Equal(declaredRoutes))
	})

	It("keeps the routes of a server-side apply that reaches the API server before the controller", func() {
		vpcName := fmt.Sprintf("vpc-main-rt-adopt-%s", sanitizeName(uniqueAllocationBase()))
		declaredRoutes := []route{internetGatewayRoute("0.0.0.0/0")}
		DeferCleanup(cleanupVpcWithMainRouteTable, vpcName)

		By("applying the Vpc and its main RouteTable as a single manifest without waiting")
		manifest, err := vpcWithMainRouteTableManifest(vpcName, declaredRoutes...)
		Expect(err).NotTo(HaveOccurred())
		Expect(applyManifestServerSide(manifest)).To(Succeed())

		By("waiting for the Vpc to report the RouteTable as its main one")
		Expect(waitVpcMainRouteTable(vpcName)).To(Equal(vpcName))

		By("checking the controller took ownership and left the declared routes alone")
		Eventually(func(g Gomega) {
			obj, err := getRouteTableObject(vpcName)
			g.Expect(err).NotTo(HaveOccurred())

			ref := routeTableControllerRef(obj)
			g.Expect(ref).NotTo(BeNil(), "routetable %s has no controller ownerReference", vpcName)
			g.Expect(ref.Kind).To(Equal("Vpc"))
			g.Expect(ref.Name).To(Equal(vpcName))

			g.Expect(obj.Spec.Vpc).To(Equal(vpcName))
			g.Expect(obj.Spec.Routes).To(Equal(declaredRoutes))
		}).Should(Succeed())
	})
})

func cleanupVpcWithMainRouteTable(vpc string) {
	// The delete webhook keeps the main RouteTable while its Vpc is
	// alive, so the Vpc goes first and takes the RouteTable with it.
	runBestEffort(repoRoot, "kubectl", "delete", "vpc", vpc, "--ignore-not-found=true")
	runBestEffort(repoRoot, "kubectl", "delete", "routetable", vpc, "--ignore-not-found=true")
}
