package e2e

import . "github.com/onsi/ginkgo/v2"

var _ = Describe("Juneau cluster connectivity", Ordered, func() {
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
