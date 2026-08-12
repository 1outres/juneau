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
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// shouldCheckReferences reports whether a validator may run the checks
// that read other objects, such as "the Vpc this spec names still
// exists".
//
// Removing a finalizer is an update, so those checks run on an object
// that is already being deleted too. Deletion order between Kinds is
// not guaranteed - tearing down a namespace can remove the Vpc before
// the NATGateway that points at it - so the object would never be
// allowed to drop its finalizers and would stay in Terminating for
// ever. Checks that only look at the object itself, such as
// immutability, keep running.
func shouldCheckReferences(obj client.Object) bool {
	return obj.GetDeletionTimestamp().IsZero()
}
