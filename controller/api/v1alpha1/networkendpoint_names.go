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

// JuneauNodeEndpointName returns the NetworkEndpoint name for a Node's
// juneau_node pseudo-pod. The controller creates the object under this
// name and the daemon on that Node reads it back, so both sides can
// find it from the Node name alone.
func JuneauNodeEndpointName(nodeName string) string {
	return "juneau-node." + nodeName
}
