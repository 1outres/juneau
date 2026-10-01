package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// VPNSpec defines a site-to-site VPN in a Vpc.
type VPNSpec struct {
	// +kubebuilder:validation:MinLength=1
	Vpc string `json:"vpc"`
	// +kubebuilder:validation:MinLength=1
	Subnet string `json:"subnet"`
	// +kubebuilder:validation:MinLength=1
	ExternalNetwork string `json:"externalNetwork"`
	// +optional
	RequestedPublicIP string `json:"requestedPublicIP,omitempty"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4294967295
	LocalASN int64 `json:"localASN"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4294967295
	RemoteASN int64 `json:"remoteASN"`
	// +kubebuilder:validation:MinLength=1
	PeerIKEID    string       `json:"peerIKEID"`
	PSKSecretRef VPNSecretRef `json:"pskSecretRef"`
}

// VPNSecretRef selects one key in a Secret in the VPN's namespace.
type VPNSecretRef struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// +kubebuilder:validation:MinLength=1
	Key string `json:"key"`
}

// VPNStatus contains non-secret addresses and the gateway readiness condition.
type VPNStatus struct {
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	PublicIP           string             `json:"publicIP,omitempty"`
	LocalTunnelIP      string             `json:"localTunnelIP,omitempty"`
	RemoteTunnelIP     string             `json:"remoteTunnelIP,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Vpc",type="string",JSONPath=".spec.vpc"
// +kubebuilder:printcolumn:name="PublicIP",type="string",JSONPath=".status.publicIP"

// VPN is the Schema for the vpns API.
type VPN struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              VPNSpec   `json:"spec,omitempty"`
	Status            VPNStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// VPNList contains a list of VPN.
type VPNList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VPN `json:"items"`
}

func init() { SchemeBuilder.Register(&VPN{}, &VPNList{}) }
