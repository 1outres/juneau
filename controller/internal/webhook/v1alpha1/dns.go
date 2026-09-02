package v1alpha1

import (
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

func validateDNSNames(names []string, path *field.Path) field.ErrorList {
	var errs field.ErrorList
	seen := map[string]struct{}{}
	for i, name := range names {
		itemPath := path.Index(i)
		if name != strings.ToLower(name) || strings.HasSuffix(name, ".") {
			errs = append(errs, field.Invalid(itemPath, name, "must be a lowercase FQDN without a trailing dot"))
			continue
		}
		for _, message := range validation.IsDNS1123Subdomain(name) {
			errs = append(errs, field.Invalid(itemPath, name, message))
		}
		if _, exists := seen[name]; exists {
			errs = append(errs, field.Duplicate(itemPath, name))
		}
		seen[name] = struct{}{}
	}
	return errs
}

func validateAllocationDNS(binding *juneauv1alpha1.AllocationDNSBinding, path *field.Path) field.ErrorList {
	if binding == nil {
		return nil
	}
	var errs field.ErrorList
	if binding.Vpc == "" {
		errs = append(errs, field.Required(path.Child("vpc"), "Vpc is required"))
	}
	if len(binding.Names) == 0 {
		errs = append(errs, field.Required(path.Child("names"), "at least one DNS name is required"))
	}
	return append(errs, validateDNSNames(binding.Names, path.Child("names"))...)
}
