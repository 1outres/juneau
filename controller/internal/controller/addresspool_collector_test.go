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

package controller

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

func TestAddressPoolCollector(t *testing.T) {
	s := scheme.Scheme
	if err := juneauv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	computed := &juneauv1alpha1.AddressPool{
		ObjectMeta: metav1.ObjectMeta{Name: "edge", Generation: 2},
		Status: juneauv1alpha1.AddressPoolStatus{
			ObservedGeneration: 2,
			TotalAddresses:     10,
			AllocatedAddresses: 3,
			AvailableAddresses: 7,
		},
	}
	notYetComputed := &juneauv1alpha1.AddressPool{ObjectMeta: metav1.ObjectMeta{Name: "new", Generation: 1}}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(computed, notYetComputed).Build()

	expected := `
# HELP juneau_addresspool_addresses Number of addresses of an AddressPool by state: total, allocated or available.
# TYPE juneau_addresspool_addresses gauge
juneau_addresspool_addresses{pool="edge",state="allocated"} 3
juneau_addresspool_addresses{pool="edge",state="available"} 7
juneau_addresspool_addresses{pool="edge",state="total"} 10
`
	if err := testutil.CollectAndCompare(NewAddressPoolCollector(c), strings.NewReader(expected)); err != nil {
		t.Fatal(err)
	}
}
