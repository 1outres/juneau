package e2e

import (
	"encoding/json"
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type allocationObjectList struct {
	Items []allocationObject `json:"items"`
}

type allocationObject struct {
	Metadata allocationMetadata `json:"metadata"`
	Spec     allocationSpec     `json:"spec"`
	Status   allocationStatus   `json:"status"`
}

type allocationMetadata struct {
	Name string `json:"name"`
}

type allocationSpec struct {
	PoolRef     allocationPoolRef     `json:"poolRef"`
	ResourceRef allocationResourceRef `json:"resourceRef"`
	Attribute   string                `json:"attribute"`
}

type allocationPoolRef struct {
	Name string `json:"name"`
}

type allocationResourceRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

type allocationStatus struct {
	VNI        uint64                `json:"vni,omitempty"`
	TableID    uint64                `json:"tableID,omitempty"`
	Phase      string                `json:"phase,omitempty"`
	Value      allocationStatusValue `json:"value,omitempty"`
	Conditions []allocationCondition `json:"conditions,omitempty"`
}

type allocationStatusValue struct {
	Number uint64 `json:"number,omitempty"`
}

type allocationCondition struct {
	Type   string `json:"type"`
	Status string `json:"status"`
}

var _ = Describe("Juneau allocator regression", Ordered, func() {
	It("allocates unique VNIs and route table IDs across concurrent custom networks", func() {
		const vpcCount = 10

		base := sanitizeName(uniqueAllocationBase())
		vpcNames := make([]string, 0, vpcCount)
		subnetNames := make([]string, 0, vpcCount*2)

		var manifest strings.Builder
		for i := 0; i < vpcCount; i++ {
			vpcName := fmt.Sprintf("vpc-%s-%02d", base, i)
			subnetA := fmt.Sprintf("subnet-a-%s-%02d", base, i)
			subnetB := fmt.Sprintf("subnet-b-%s-%02d", base, i)
			cidrBase := 40 + i*2

			vpcNames = append(vpcNames, vpcName)
			subnetNames = append(subnetNames, subnetA, subnetB)

			fmt.Fprintf(&manifest, `apiVersion: juneau.loutres.me/v1alpha1
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
  cidr: 10.%d.0.0/24
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: %s
spec:
  vpc: %s
  cidr: 10.%d.0.0/24
---
`, vpcName, subnetA, vpcName, cidrBase, subnetB, vpcName, cidrBase+1)
		}

		DeferCleanup(func() {
			for _, subnetName := range subnetNames {
				runBestEffort(repoRoot, "kubectl", "delete", "subnet", subnetName, "--ignore-not-found=true")
			}
			for _, vpcName := range vpcNames {
				runBestEffort(repoRoot, "kubectl", "delete", "routetable", vpcName, "--ignore-not-found=true")
				runBestEffort(repoRoot, "kubectl", "delete", "vpc", vpcName, "--ignore-not-found=true")
			}
		})

		Expect(applyManifest(manifest.String())).To(Succeed())

		Eventually(func(g Gomega) {
			subnets := mustGetAllocationObjects(g, "subnet")
			vniOwners := map[uint64]string{}
			for _, subnetName := range subnetNames {
				subnet := findAllocationObjectByName(subnets, subnetName)
				g.Expect(subnet).NotTo(BeNil(), "missing subnet %s", subnetName)
				g.Expect(statusCondition(subnet.Status.Conditions, "Ready")).To(Equal("True"), "subnet %s not ready", subnetName)
				g.Expect(subnet.Status.VNI).NotTo(BeZero(), "subnet %s missing VNI", subnetName)
				if owner, exists := vniOwners[subnet.Status.VNI]; exists {
					g.Expect(subnet.Metadata.Name).To(Equal(owner), "duplicate VNI %d for subnets %s and %s", subnet.Status.VNI, owner, subnet.Metadata.Name)
				} else {
					vniOwners[subnet.Status.VNI] = subnet.Metadata.Name
				}
			}

			routeTables := mustGetAllocationObjects(g, "routetable")
			tableOwners := map[uint64]string{}
			for _, vpcName := range vpcNames {
				routeTable := findAllocationObjectByName(routeTables, vpcName)
				g.Expect(routeTable).NotTo(BeNil(), "missing route table %s", vpcName)
				g.Expect(statusCondition(routeTable.Status.Conditions, "Ready")).To(Equal("True"), "route table %s not ready", vpcName)
				g.Expect(routeTable.Status.TableID).NotTo(BeZero(), "route table %s missing tableID", vpcName)
				if owner, exists := tableOwners[routeTable.Status.TableID]; exists {
					g.Expect(routeTable.Metadata.Name).To(Equal(owner), "duplicate tableID %d for route tables %s and %s", routeTable.Status.TableID, owner, routeTable.Metadata.Name)
				} else {
					tableOwners[routeTable.Status.TableID] = routeTable.Metadata.Name
				}
			}

			claims := mustGetAllocationObjects(g, "allocationclaim")
			claimNumbers := map[string]uint64{}
			for _, claim := range claims {
				if claim.Spec.ResourceRef.Kind != "Subnet" && claim.Spec.ResourceRef.Kind != "RouteTable" {
					continue
				}
				if !containsName(subnetNames, claim.Spec.ResourceRef.Name) && !containsName(vpcNames, claim.Spec.ResourceRef.Name) {
					continue
				}
				g.Expect(claim.Status.Phase).To(Equal("Allocated"), "claim %s not allocated", claim.Metadata.Name)
				g.Expect(claim.Status.Value.Number).NotTo(BeZero(), "claim %s missing value.number", claim.Metadata.Name)
				claimKey := fmt.Sprintf("%s/%s/%s", claim.Spec.ResourceRef.Kind, claim.Spec.ResourceRef.Name, claim.Spec.Attribute)
				claimNumbers[claimKey] = claim.Status.Value.Number
			}

			for _, subnetName := range subnetNames {
				claimKey := fmt.Sprintf("Subnet/%s/status.vni", subnetName)
				subnet := findAllocationObjectByName(subnets, subnetName)
				g.Expect(claimNumbers).To(HaveKey(claimKey))
				g.Expect(claimNumbers[claimKey]).To(Equal(subnet.Status.VNI))
			}
			for _, vpcName := range vpcNames {
				claimKey := fmt.Sprintf("RouteTable/%s/status.tableID", vpcName)
				routeTable := findAllocationObjectByName(routeTables, vpcName)
				g.Expect(claimNumbers).To(HaveKey(claimKey))
				g.Expect(claimNumbers[claimKey]).To(Equal(routeTable.Status.TableID))
			}
		}).Should(Succeed())
	})
})

func uniqueAllocationBase() string {
	return fmt.Sprintf("alloc-%d", GinkgoRandomSeed())
}

func mustGetAllocationObjects(g Gomega, resource string) []allocationObject {
	out, err := kubectlOutput(repoRoot, "get", resource, "-o", "json")
	g.Expect(err).NotTo(HaveOccurred())

	var list allocationObjectList
	g.Expect(json.Unmarshal([]byte(out), &list)).To(Succeed())
	return list.Items
}

func findAllocationObjectByName(objects []allocationObject, name string) *allocationObject {
	for i := range objects {
		if objects[i].Metadata.Name == name {
			return &objects[i]
		}
	}
	return nil
}

func statusCondition(conditions []allocationCondition, conditionType string) string {
	for _, condition := range conditions {
		if condition.Type == conditionType {
			return condition.Status
		}
	}
	return ""
}

func containsName(names []string, target string) bool {
	for _, name := range names {
		if name == target {
			return true
		}
	}
	return false
}
