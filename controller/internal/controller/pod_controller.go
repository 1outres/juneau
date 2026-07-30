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
	"context"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

const (
	podAnnSubnet           = "juneau.loutres.me/subnet"
	podAnnAddress          = "juneau.loutres.me/address"
	podAnnSecurityGroups   = "juneau.loutres.me/security-groups"
	podAnnNetworkInterface = "juneau.loutres.me/network-interface"
	defaultIfName          = "eth0"
	requeueDelay           = 5 * time.Second
)

// PodReconciler reconciles a Pod object for NetworkInterface provisioning.
type PodReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=networkinterfaces,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=networkinterfaceattachments,verbs=get;list;watch;create;delete

// Reconcile creates a pod-scoped NetworkInterfaceAttachment. Pods without an
// explicit persistent NetworkInterface receive a Pod-owned interface so the
// default Kubernetes experience remains automatic.
func (r *PodReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var pod corev1.Pod
	if err := r.Get(ctx, req.NamespacedName, &pod); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to get Pod", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if !pod.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	annotations := pod.GetAnnotations()
	if pod.Spec.HostNetwork {
		return ctrl.Result{}, nil
	}
	if _, isMirror := annotations["kubernetes.io/config.mirror"]; isMirror {
		return ctrl.Result{}, nil
	}

	ifName := "eth0"

	if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
		niName := pod.Name + "." + ifName
		var attachment juneauv1alpha1.NetworkInterfaceAttachment
		if err := r.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: niName}, &attachment); err != nil {
			if errors.IsNotFound(err) {
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, r.Delete(ctx, &attachment)
	}

	networkInterfaceName := annotations[podAnnNetworkInterface]
	subnetName := annotations[podAnnSubnet]

	if pod.Spec.NodeName == "" {
		// ノード未確定なので少し待つ
		return ctrl.Result{RequeueAfter: requeueDelay}, nil
	}

	autoManaged := networkInterfaceName == ""
	if autoManaged {
		if subnetName == "" {
			subnetName = "default"
		}
		var subnet juneauv1alpha1.Subnet
		if err := r.Get(ctx, client.ObjectKey{Name: subnetName}, &subnet); err != nil {
			if errors.IsNotFound(err) {
				return ctrl.Result{RequeueAfter: requeueDelay}, nil
			}
			return ctrl.Result{}, err
		}
	} else {
		var networkInterface juneauv1alpha1.NetworkInterface
		if err := r.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: networkInterfaceName}, &networkInterface); err != nil {
			if errors.IsNotFound(err) {
				return ctrl.Result{RequeueAfter: requeueDelay}, nil
			}
			return ctrl.Result{}, err
		}
		subnetName = networkInterface.Spec.Subnet
	}

	if autoManaged {
		networkInterfaceName = pod.Name + "." + ifName
		nwiface := &juneauv1alpha1.NetworkInterface{}
		nwiface.SetName(networkInterfaceName)
		nwiface.SetNamespace(pod.Namespace)
		_, err := ctrl.CreateOrUpdate(ctx, r.Client, nwiface, func() error {
			nwiface.Spec.Subnet = subnetName
			nwiface.Spec.Address = annotations[podAnnAddress]
			nwiface.Spec.SecurityGroups = ParsePodSecurityGroups(annotations[podAnnSecurityGroups])
			return ctrl.SetControllerReference(&pod, nwiface, r.Scheme)
		})
		if err != nil {
			if errors.IsConflict(err) || errors.IsAlreadyExists(err) {
				return ctrl.Result{Requeue: true}, nil
			}
			logger.Error(err, "unable to create or update automatic NetworkInterface")
			return ctrl.Result{}, err
		}
	}

	attachment := &juneauv1alpha1.NetworkInterfaceAttachment{}
	attachment.SetName(pod.Name + "." + ifName)
	attachment.SetNamespace(pod.Namespace)
	_, err := ctrl.CreateOrUpdate(ctx, r.Client, attachment, func() error {
		if attachment.UID != "" && !metav1.IsControlledBy(attachment, &pod) {
			return errors.NewAlreadyExists(
				juneauv1alpha1.GroupVersion.WithResource("networkinterfaceattachments").GroupResource(),
				attachment.Name,
			)
		}
		attachment.Spec.NetworkInterfaceRef = networkInterfaceName
		attachment.Spec.PodRef = juneauv1alpha1.NetworkInterfaceAttachmentPodReference{
			Name:      pod.Name,
			UID:       string(pod.UID),
			Interface: ifName,
		}
		attachment.Spec.NodeName = pod.Spec.NodeName
		return ctrl.SetControllerReference(&pod, attachment, r.Scheme)
	})
	if err != nil {
		if errors.IsConflict(err) || errors.IsAlreadyExists(err) {
			return ctrl.Result{RequeueAfter: requeueDelay}, nil
		}
		logger.Error(err, "unable to create NetworkInterfaceAttachment")
		return ctrl.Result{}, err
	}

	if autoManaged {
		var nwiface juneauv1alpha1.NetworkInterface
		if err := r.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: networkInterfaceName}, &nwiface); err != nil {
			return ctrl.Result{}, err
		}
		desired := &juneauv1alpha1.NetworkInterfaceAttachmentReference{Name: attachment.Name, UID: attachment.UID}
		if nwiface.Spec.AttachmentRef == nil ||
			nwiface.Spec.AttachmentRef.Name != desired.Name ||
			nwiface.Spec.AttachmentRef.UID != desired.UID {
			nwiface.Spec.AttachmentRef = desired
			if err := r.Update(ctx, &nwiface); err != nil {
				if errors.IsConflict(err) {
					return ctrl.Result{Requeue: true}, nil
				}
				return ctrl.Result{}, err
			}
		}
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *PodReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		Named("pod").
		Complete(r)
}

// ParsePodSecurityGroups parses the comma-separated value of the
// juneau.loutres.me/security-groups Pod annotation into a deduplicated,
// sorted slice. Empty / whitespace-only entries are dropped.
//
// Sorting yields a stable spec.securityGroups regardless of how the user
// wrote the annotation, which keeps NetworkInterface diffs minimal.
func ParsePodSecurityGroups(annotation string) []string {
	if strings.TrimSpace(annotation) == "" {
		return nil
	}
	parts := strings.Split(annotation, ",")
	seen := make(map[string]struct{}, len(parts))
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		name := strings.TrimSpace(p)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
