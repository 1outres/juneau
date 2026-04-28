package e2e

import (
	"encoding/json"
	"fmt"
	"strings"

	. "github.com/onsi/gomega"
)

type natGatewayObject struct {
	Metadata natGatewayMeta   `json:"metadata"`
	Spec     natGatewaySpec   `json:"spec"`
	Status   natGatewayStatus `json:"status"`
}

type natGatewayMeta struct {
	Name string `json:"name"`
}

type natGatewaySpec struct {
	Vpc             string `json:"vpc"`
	ExternalNetwork string `json:"externalNetwork"`
}

type natGatewayStatus struct {
	GatewayID  uint32                       `json:"gatewayID,omitempty"`
	Conditions []bgpNodeStateConditionEntry `json:"conditions,omitempty"`
}

type externalNetworkAttachmentObject struct {
	Metadata externalNetworkAttachmentMeta   `json:"metadata"`
	Spec     externalNetworkAttachmentSpec   `json:"spec"`
	Status   externalNetworkAttachmentStatus `json:"status"`
}

type externalNetworkAttachmentList struct {
	Items []externalNetworkAttachmentObject `json:"items"`
}

type externalNetworkAttachmentMeta struct {
	Name            string                                  `json:"name"`
	OwnerReferences []externalNetworkAttachmentOwnerRef     `json:"ownerReferences,omitempty"`
}

type externalNetworkAttachmentOwnerRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

type externalNetworkAttachmentSpec struct {
	ExternalNetwork string `json:"externalNetwork"`
	NodeName        string `json:"nodeName"`
}

type externalNetworkAttachmentStatus struct {
	AssignedIP string                       `json:"assignedIP,omitempty"`
	Conditions []bgpNodeStateConditionEntry `json:"conditions,omitempty"`
}

type routeTableObject struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Status struct {
		TableID uint32                       `json:"tableID,omitempty"`
		Routes  []routeTableRoute            `json:"routes,omitempty"`
		Conditions []bgpNodeStateConditionEntry `json:"conditions,omitempty"`
	} `json:"status"`
}

type routeTableRoute struct {
	Dst string `json:"dst"`
	Via struct {
		Type       string `json:"type"`
		NATGateway string `json:"natGateway,omitempty"`
	} `json:"via"`
}

func applyNATGateway(name, vpc, externalNetwork string) error {
	manifest := fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: NATGateway
metadata:
  name: %s
spec:
  vpc: %s
  externalNetwork: %s
`, name, vpc, externalNetwork)
	return applyManifest(manifest)
}

func getNATGateway(name string) (*natGatewayObject, error) {
	out, err := kubectlOutput(repoRoot, "get", "natgateway", name, "-o", "json")
	if err != nil {
		return nil, err
	}
	var obj natGatewayObject
	if err := json.Unmarshal([]byte(out), &obj); err != nil {
		return nil, fmt.Errorf("decode natgateway/%s: %w", name, err)
	}
	return &obj, nil
}

func waitNATGatewayReady(name string) {
	Eventually(func(g Gomega) {
		obj, err := getNATGateway(name)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(obj.Status.GatewayID).NotTo(BeZero(), "natgateway %s missing GatewayID", name)
		g.Expect(conditionStatus(obj.Status.Conditions, "Ready")).To(Equal("True"), "natgateway %s Ready condition", name)
	}).Should(Succeed())
}

func listExternalNetworkAttachments() ([]externalNetworkAttachmentObject, error) {
	out, err := kubectlOutput(repoRoot, "get", "externalnetworkattachments", "-o", "json")
	if err != nil {
		return nil, err
	}
	var list externalNetworkAttachmentList
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		return nil, fmt.Errorf("decode externalnetworkattachments: %w", err)
	}
	return list.Items, nil
}

func waitExternalNetworkAttachmentReady(name string) {
	Eventually(func(g Gomega) {
		out, err := kubectlOutput(repoRoot, "get", "externalnetworkattachment", name, "-o", "json")
		g.Expect(err).NotTo(HaveOccurred())
		var obj externalNetworkAttachmentObject
		g.Expect(json.Unmarshal([]byte(out), &obj)).To(Succeed())
		g.Expect(strings.TrimSpace(obj.Status.AssignedIP)).NotTo(BeEmpty(), "attachment %s AssignedIP empty", name)
		g.Expect(conditionStatus(obj.Status.Conditions, "Ready")).To(Equal("True"), "attachment %s Ready condition", name)
	}).Should(Succeed())
}

func getRouteTableObject(name string) (*routeTableObject, error) {
	out, err := kubectlOutput(repoRoot, "get", "routetable", name, "-o", "json")
	if err != nil {
		return nil, err
	}
	var obj routeTableObject
	if err := json.Unmarshal([]byte(out), &obj); err != nil {
		return nil, fmt.Errorf("decode routetable/%s: %w", name, err)
	}
	return &obj, nil
}

func dumpNATDiagnostics() {
	dumpResource("natgateways")
	dumpResource("externalnetworkattachments")
	dumpResource("externalnetworks")
	dumpResource("addresspools")
	dumpResource("routetables")
}
