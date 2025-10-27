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

package cert

import (
	"context"
	"fmt"
	"os"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// GetNodeIP retrieves the node IP address from the NODE_NAME environment variable
func GetNodeIP(ctx context.Context, k8sClient client.Client) (string, error) {
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		return "", fmt.Errorf("NODE_NAME environment variable is not set")
	}

	// Get the node object
	node := &corev1.Node{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: nodeName}, node); err != nil {
		return "", fmt.Errorf("failed to get node %s: %w", nodeName, err)
	}

	// Try to get InternalIP first, then ExternalIP
	for _, addr := range node.Status.Addresses {
		if addr.Type == corev1.NodeInternalIP {
			return addr.Address, nil
		}
	}

	for _, addr := range node.Status.Addresses {
		if addr.Type == corev1.NodeExternalIP {
			return addr.Address, nil
		}
	}

	return "", fmt.Errorf("no IP address found for node %s", nodeName)
}

// GetNodeName returns the node name from NODE_NAME environment variable
func GetNodeName() (string, error) {
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		return "", fmt.Errorf("NODE_NAME environment variable is not set")
	}
	return nodeName, nil
}
