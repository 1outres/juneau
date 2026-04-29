package e2e

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Bringup smoke spec: anchors SynchronizedBeforeSuite when the suite is
// invoked with --ginkgo.label-filter=bringup. Provides a way to spin up the
// kind cluster and full controller/daemon/bgp-speaker stack without running
// the heavier behavioral specs. Combine with E2E_KEEP_CLUSTER=true to keep
// the environment for manual exploration.
var _ = Describe("Bringup", Label("bringup"), func() {
	It("reports cluster is ready", func() {
		Expect(workerNodes).NotTo(BeEmpty(), "worker nodes should be discovered")
		_, _ = fmt.Fprintf(GinkgoWriter, "kind cluster %q is up with %d worker(s): %v\n",
			clusterName, len(workerNodes), workerNodes)
		if bgpRouter != nil {
			_, _ = fmt.Fprintf(GinkgoWriter, "BGP peer router %q at %s\n", bgpRouter.name, bgpRouter.ip)
		}
	})
})
