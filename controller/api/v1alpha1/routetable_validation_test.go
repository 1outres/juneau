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
	"testing"

	"k8s.io/apimachinery/pkg/util/validation/field"
)

func TestValidateRouteEndpointReference(t *testing.T) {
	path := field.NewPath("spec", "routes").Index(0).Child("via", "endpoint")
	valid := RouteEndpointReference{Namespace: "net", AllocationIdentity: "vmi.vm-router", Interface: "eth0"}

	cases := []struct {
		name      string
		mutate    func(*RouteEndpointReference)
		wantField string
	}{
		{name: "valid", mutate: func(*RouteEndpointReference) {}},
		{name: "no namespace", mutate: func(r *RouteEndpointReference) { r.Namespace = "" }, wantField: path.Child("namespace").String()},
		{name: "namespace not a label", mutate: func(r *RouteEndpointReference) { r.Namespace = "a.b" }, wantField: path.Child("namespace").String()},
		{name: "no identity", mutate: func(r *RouteEndpointReference) { r.AllocationIdentity = "" }, wantField: path.Child("allocationIdentity").String()},
		{name: "identity not a subdomain", mutate: func(r *RouteEndpointReference) { r.AllocationIdentity = "Router_A" }, wantField: path.Child("allocationIdentity").String()},
		{name: "no interface", mutate: func(r *RouteEndpointReference) { r.Interface = "" }, wantField: path.Child("interface").String()},
		{name: "interface too long", mutate: func(r *RouteEndpointReference) { r.Interface = "eth0123456" }, wantField: path.Child("interface").String()},
		{name: "interface not a label", mutate: func(r *RouteEndpointReference) { r.Interface = "Eth0" }, wantField: path.Child("interface").String()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ref := valid
			tc.mutate(&ref)
			errs := ValidateRouteEndpointReference(ref, path)
			if tc.wantField == "" {
				if len(errs) > 0 {
					t.Fatalf("unexpected errors: %v", errs)
				}
				return
			}
			if len(errs) == 0 {
				t.Fatalf("ValidateRouteEndpointReference(%+v) accepted an invalid reference", ref)
			}
			for _, err := range errs {
				if err.Field != tc.wantField {
					t.Errorf("error at %q, want %q", err.Field, tc.wantField)
				}
			}
		})
	}
}
