package v1alpha1

import (
	"context"
	"net"

	juneau "github.com/1outres/juneau/controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (v *VPNCustomValidator) validate(ctx context.Context, vpn, old *juneau.VPN) error {
	errs := validateVPNSpec(vpn, old)
	if shouldCheckReferences(vpn) {
		refErrs, err := v.validateVPNReferences(ctx, vpn)
		if err != nil {
			return err
		}
		errs = append(errs, refErrs...)
	}
	if len(errs) > 0 {
		return apierrors.NewInvalid(schema.GroupKind{Group: juneau.GroupVersion.Group, Kind: "VPN"}, vpn.Name, errs)
	}
	return nil
}

func validateVPNSpec(vpn, old *juneau.VPN) field.ErrorList {
	p := field.NewPath("spec")
	s := vpn.Spec
	var errs field.ErrorList
	if vpn.Namespace == "" {
		errs = append(errs, field.Required(field.NewPath("metadata", "namespace"), "VPN must be namespaced"))
	}
	if s.Vpc == "" {
		errs = append(errs, field.Required(p.Child("vpc"), "Vpc is required"))
	}
	if s.Subnet == "" {
		errs = append(errs, field.Required(p.Child("subnet"), "Subnet is required"))
	}
	if s.ExternalNetwork == "" {
		errs = append(errs, field.Required(p.Child("externalNetwork"), "ExternalNetwork is required"))
	}
	for _, ref := range []struct {
		name string
		path *field.Path
	}{
		{s.Vpc, p.Child("vpc")}, {s.Subnet, p.Child("subnet")}, {s.ExternalNetwork, p.Child("externalNetwork")}, {s.PSKSecretRef.Name, p.Child("pskSecretRef", "name")},
	} {
		if ref.name != "" && len(validation.IsDNS1123Subdomain(ref.name)) != 0 {
			errs = append(errs, field.Invalid(ref.path, ref.name, "must be a DNS name"))
		}
	}
	if s.LocalASN < 1 || s.LocalASN > 4294967295 {
		errs = append(errs, field.Invalid(p.Child("localASN"), s.LocalASN, "ASN must be between 1 and 4294967295"))
	}
	if s.RemoteASN < 1 || s.RemoteASN > 4294967295 || s.RemoteASN == s.LocalASN {
		errs = append(errs, field.Invalid(p.Child("remoteASN"), s.RemoteASN, "ASNs must be in range and different"))
	}
	if s.PeerIKEID == "" {
		errs = append(errs, field.Required(p.Child("peerIKEID"), "peer IKE ID is required"))
	}
	if s.RequestedPublicIP != "" {
		ip := net.ParseIP(s.RequestedPublicIP)
		if ip == nil || ip.To4() == nil || ip.String() != s.RequestedPublicIP {
			errs = append(errs, field.Invalid(p.Child("requestedPublicIP"), s.RequestedPublicIP, "must be an IPv4 address"))
		}
	}
	if s.PSKSecretRef.Name == "" {
		errs = append(errs, field.Required(p.Child("pskSecretRef", "name"), "Secret name is required"))
	}
	if s.PSKSecretRef.Key == "" {
		errs = append(errs, field.Required(p.Child("pskSecretRef", "key"), "Secret key is required"))
	}
	if old != nil {
		if s.Vpc != old.Spec.Vpc {
			errs = append(errs, field.Forbidden(p.Child("vpc"), "placement is immutable"))
		}
		if s.Subnet != old.Spec.Subnet {
			errs = append(errs, field.Forbidden(p.Child("subnet"), "placement is immutable"))
		}
		if s.ExternalNetwork != old.Spec.ExternalNetwork {
			errs = append(errs, field.Forbidden(p.Child("externalNetwork"), "placement is immutable"))
		}
		if s.RequestedPublicIP != old.Spec.RequestedPublicIP {
			errs = append(errs, field.Forbidden(p.Child("requestedPublicIP"), "placement is immutable"))
		}
	}
	return errs
}

func (v *VPNCustomValidator) validateVPNReferences(ctx context.Context, vpn *juneau.VPN) (field.ErrorList, error) {
	s := vpn.Spec
	p := field.NewPath("spec")
	var errs field.ErrorList
	if s.Vpc != "" && len(validation.IsDNS1123Subdomain(s.Vpc)) == 0 {
		var obj juneau.Vpc
		if err := v.Get(ctx, client.ObjectKey{Name: s.Vpc}, &obj); err != nil {
			if !apierrors.IsNotFound(err) {
				return nil, err
			}
			errs = append(errs, field.Invalid(p.Child("vpc"), s.Vpc, "Vpc does not exist"))
		} else if !obj.DeletionTimestamp.IsZero() {
			errs = append(errs, field.Forbidden(p.Child("vpc"), "Vpc is being deleted"))
		}
	}
	if s.Subnet != "" && len(validation.IsDNS1123Subdomain(s.Subnet)) == 0 {
		var obj juneau.Subnet
		if err := v.Get(ctx, client.ObjectKey{Name: s.Subnet}, &obj); err != nil {
			if !apierrors.IsNotFound(err) {
				return nil, err
			}
			errs = append(errs, field.Invalid(p.Child("subnet"), s.Subnet, "Subnet does not exist"))
		} else if obj.Spec.Vpc != s.Vpc || !obj.DeletionTimestamp.IsZero() {
			errs = append(errs, field.Invalid(p.Child("subnet"), s.Subnet, "Subnet must belong to the Vpc and must not be deleting"))
		}
	}
	if s.ExternalNetwork != "" && len(validation.IsDNS1123Subdomain(s.ExternalNetwork)) == 0 {
		var obj juneau.ExternalNetwork
		if err := v.Get(ctx, client.ObjectKey{Name: s.ExternalNetwork}, &obj); err != nil {
			if !apierrors.IsNotFound(err) {
				return nil, err
			}
			errs = append(errs, field.Invalid(p.Child("externalNetwork"), s.ExternalNetwork, "ExternalNetwork does not exist"))
		} else if !obj.DeletionTimestamp.IsZero() {
			errs = append(errs, field.Forbidden(p.Child("externalNetwork"), "ExternalNetwork is being deleted"))
		}
	}
	if s.PSKSecretRef.Name != "" && vpn.Namespace != "" && len(validation.IsDNS1123Subdomain(s.PSKSecretRef.Name)) == 0 {
		var secret corev1.Secret
		if err := v.Get(ctx, client.ObjectKey{Namespace: vpn.Namespace, Name: s.PSKSecretRef.Name}, &secret); err != nil {
			if !apierrors.IsNotFound(err) {
				return nil, err
			}
			errs = append(errs, field.Invalid(p.Child("pskSecretRef", "name"), s.PSKSecretRef.Name, "Secret does not exist in the VPN namespace"))
		} else if len(secret.Data[s.PSKSecretRef.Key]) == 0 {
			errs = append(errs, field.Invalid(p.Child("pskSecretRef", "key"), s.PSKSecretRef.Key, "Secret key must contain a PSK"))
		}
	}
	return errs, nil
}
