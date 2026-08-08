/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// validateRetainReference checks a spec.retainWhile on every resource that
// carries one. A nil reference is valid, because retention is opt-in; a
// reference that is present has to name an object the controller can read.
func validateRetainReference(ref *juneauv1alpha1.RetainReference, path *field.Path) field.ErrorList {
	if ref == nil {
		return nil
	}

	var errs field.ErrorList
	if ref.APIVersion == "" {
		errs = append(errs, field.Required(path.Child("apiVersion"), "apiVersion of the retained object is required"))
	}
	if ref.Kind == "" {
		errs = append(errs, field.Required(path.Child("kind"), "kind of the retained object is required"))
	}
	if ref.Name == "" {
		errs = append(errs, field.Required(path.Child("name"), "name of the retained object is required"))
	} else {
		for _, msg := range validation.IsDNS1123Subdomain(ref.Name) {
			errs = append(errs, field.Invalid(path.Child("name"), ref.Name, msg))
		}
	}
	if ref.Namespace != "" {
		for _, msg := range validation.IsDNS1123Label(ref.Namespace) {
			errs = append(errs, field.Invalid(path.Child("namespace"), ref.Namespace, msg))
		}
	}
	return errs
}

// retainReferenceEqual reports whether two retain references point at the
// same object, so that callers can keep the field immutable.
func retainReferenceEqual(a, b *juneauv1alpha1.RetainReference) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
