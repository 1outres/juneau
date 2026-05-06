// Package topology walks the Juneau resource graph rooted at a single
// object (Pod, Vpc, Subnet, Service, NetworkInterface) and returns a
// flat, presenter-friendly snapshot of the connected resources.
//
// The package is the only place CRD field semantics are consulted; the
// cmd/* layer above and the output/* layer below treat the returned
// *Context structs as opaque DTOs.
//
// All public functions take a View — the I/O abstraction in view.go.
// Tests substitute a fake View; production passes the kubeView in
// kubeview.go. No function in this package opens a kube client itself.
package topology

// Annotation keys are duplicated from controller/internal/webhook and
// controller/internal/controller because those packages are
// internal/-scoped. Keep this block in sync with:
//   - controller/internal/controller/pod_controller.go
//   - controller/internal/webhook/v1alpha1/service_webhook.go
//   - controller/internal/webhook/v1alpha1/pod_webhook.go
//
// Once the controller exposes these as public constants under
// controller/api/v1alpha1, replace this block with imports and delete
// the duplication.
const (
	// AnnotationPodSubnet selects the Subnet a Pod is admitted into.
	AnnotationPodSubnet = "juneau.loutres.me/subnet"
	// AnnotationPodAddress requests a specific IP for a Pod.
	AnnotationPodAddress = "juneau.loutres.me/address"
	// AnnotationPodSecurityGroups is a comma-separated list of SG
	// names attached to the Pod's NetworkInterface.
	AnnotationPodSecurityGroups = "juneau.loutres.me/security-groups"

	// AnnotationServiceVpc selects the Vpc a Service belongs to.
	// Empty (or "default") implicitly resolves to the default Vpc.
	AnnotationServiceVpc = "juneau.loutres.me/vpc"
	// AnnotationServiceShared marks a Service as reachable from
	// other Vpcs that have spec.service.consume=true (subject to the
	// per-Service ACL when set). Value "true" (string) opts in.
	AnnotationServiceShared = "juneau.loutres.me/shared-service"
	// AnnotationServiceAllowedConsumerVpcs whitelists consumer Vpcs
	// for a shared Service. Comma-separated Vpc names; absent means
	// every consume-enabled Vpc is permitted.
	AnnotationServiceAllowedConsumerVpcs = "juneau.loutres.me/shared-service-allowed-consumer-vpcs"
)

// DefaultVpcName is the well-known name of the default Vpc that
// Juneau bootstraps. Services and Pods that omit Vpc/Subnet
// annotations land here.
const DefaultVpcName = "default"
