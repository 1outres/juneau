package e2e

import . "github.com/onsi/ginkgo/v2"

// Each table entry runs in an isolated namespace + VPC + subnet pair
// (CIDRs are deterministically derived from the scenario name, see
// cidrForScenario), so the matrix is safely parallelizable across
// Ginkgo processes — Ordered would otherwise pin all 8 entries to a
// single node.
var _ = Describe("Juneau cluster connectivity", func() {
	DescribeTable("connectivity matrix", func(s connectivityScenario) {
		runConnectivityScenario(s)
	},
		Entry("pod to pod, same node, default vpc, default subnet", connectivityScenario{
			name:      "pod-to-pod-same-node-default",
			target:    targetPodIP,
			placement: placementSameNode,
			network:   networkDefault,
		}),
		Entry("pod to pod, diff node, default vpc, default subnet", connectivityScenario{
			name:      "pod-to-pod-diff-node-default",
			target:    targetPodIP,
			placement: placementDifferentNodes,
			network:   networkDefault,
		}),
		Entry("pod to svc, same node, default vpc, default subnet", connectivityScenario{
			name:      "pod-to-svc-same-node-default",
			target:    targetService,
			placement: placementSameNode,
			network:   networkDefault,
		}),
		Entry("pod to svc, diff node, default vpc, default subnet", connectivityScenario{
			name:      "pod-to-svc-diff-node-default",
			target:    targetService,
			placement: placementDifferentNodes,
			network:   networkDefault,
		}),
		Entry("pod to pod, same node, same vpc, same subnet", connectivityScenario{
			name:      "pod-to-pod-same-node-same-custom-subnet",
			target:    targetPodIP,
			placement: placementSameNode,
			network:   networkSameCustomSubnet,
		}),
		Entry("pod to pod, diff node, same vpc, same subnet", connectivityScenario{
			name:      "pod-to-pod-diff-node-same-custom-subnet",
			target:    targetPodIP,
			placement: placementDifferentNodes,
			network:   networkSameCustomSubnet,
		}),
		Entry("pod to pod, same node, same vpc, diff subnet", connectivityScenario{
			name:      "pod-to-pod-same-node-different-custom-subnets",
			target:    targetPodIP,
			placement: placementSameNode,
			network:   networkDifferentCustomSubnets,
		}),
		Entry("pod to pod, diff node, same vpc, diff subnet", connectivityScenario{
			name:      "pod-to-pod-diff-node-different-custom-subnets",
			target:    targetPodIP,
			placement: placementDifferentNodes,
			network:   networkDifferentCustomSubnets,
		}),
	)
})

func applyManifest(manifest string) error {
	return runWithStdin(repoRoot, manifest, "kubectl", "apply", "-f", "-")
}

const e2eFieldManager = "juneau-e2e"

// applyManifestServerSide applies a manifest the way the guides tell
// users to apply a Vpc together with its main RouteTable. Client-side
// apply reads the object and creates it when the read found nothing, so
// a controller creating the same object in between makes the create fail
// with AlreadyExists. Server-side apply is a single create-or-merge
// request and cannot lose that race.
func applyManifestServerSide(manifest string) error {
	return runWithStdin(repoRoot, manifest, "kubectl", "apply", "--server-side",
		"--field-manager="+e2eFieldManager, "-f", "-")
}
