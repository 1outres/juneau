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
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/controller/internal/podnetwork"
	"github.com/1outres/juneau/controller/internal/workload"
)

const (
	requeueDelay = 5 * time.Second

	// networkInterfacePodUIDIndex finds every NetworkInterface of one pod
	// instance, including NICs the pod has stopped asking for.
	networkInterfacePodUIDIndex = "spec.podRef.uid"
)

// PodReconciler reconciles a Pod object for NetworkInterface provisioning.
type PodReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=networkinterfaces,verbs=get;list;watch;create;update;delete

// Reconcile creates one NetworkInterface per NIC a Pod asks for.
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

	if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
		return ctrl.Result{}, r.deleteNetworkInterfaces(ctx, &pod, nil)
	}

	attachments, err := juneauv1alpha1.PodNetworkAttachments(annotations)
	if err != nil {
		logger.Error(err, "unable to read the network annotations of the Pod", "name", req.NamespacedName)
		return ctrl.Result{}, reconcile.TerminalError(err)
	}
	dnsNames, err := juneauv1alpha1.ParseDNSNames(annotations[juneauv1alpha1.PodAnnotationDNSNames])
	if err != nil {
		logger.Error(err, "unable to read DNS names of the Pod", "name", req.NamespacedName)
		return ctrl.Result{}, reconcile.TerminalError(err)
	}

	if pod.Spec.NodeName == "" {
		// ノード未確定なので少し待つ
		return ctrl.Result{RequeueAfter: requeueDelay}, nil
	}

	missing, err := r.findMissingNetwork(ctx, attachments)
	if err != nil {
		return ctrl.Result{}, err
	}
	if missing != "" {
		logger.Info("waiting for the network of a Pod NIC", "name", req.NamespacedName, "network", missing)
		return ctrl.Result{RequeueAfter: requeueDelay}, nil
	}

	wanted := make(map[string]struct{}, len(attachments))
	for _, attachment := range attachments {
		wanted[attachment.Interface] = struct{}{}
		if err := r.applyNetworkInterface(ctx, &pod, attachment, dnsNames); err != nil {
			if errors.IsConflict(err) || errors.IsAlreadyExists(err) {
				return ctrl.Result{Requeue: true}, nil
			}
			logger.Error(err, "unable to create or update NetworkInterface", "interface", attachment.Interface)
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, r.deleteNetworkInterfaces(ctx, &pod, wanted)
}

// findMissingNetwork returns the first network a NIC needs and the
// cluster does not have. Nothing is provisioned until every NIC can be
// built, so a pod never comes up holding only some of the NICs it asked
// for.
func (r *PodReconciler) findMissingNetwork(ctx context.Context, attachments []juneauv1alpha1.PodNetworkAttachment) (string, error) {
	for _, attachment := range attachments {
		ref := podnetwork.AttachmentReference(attachment)
		if _, err := podnetwork.Resolve(ctx, r.Client, ref); err != nil {
			if errors.IsNotFound(err) {
				return ref.String(), nil
			}
			return "", err
		}
	}
	return "", nil
}

func (r *PodReconciler) applyNetworkInterface(ctx context.Context, pod *corev1.Pod, attachment juneauv1alpha1.PodNetworkAttachment, dnsNames []string) error {
	nwiface := &juneauv1alpha1.NetworkInterface{}
	nwiface.SetName(networkInterfaceNameForPod(pod.Name, attachment.Interface))
	nwiface.SetNamespace(pod.Namespace)

	_, err := ctrl.CreateOrUpdate(ctx, r.Client, nwiface, func() error {
		nwiface.Spec.PodRef.Name = pod.Name
		nwiface.Spec.PodRef.UID = string(pod.UID)
		nwiface.Spec.PodRef.Interface = attachment.Interface

		nwiface.Spec.NodeName = pod.Spec.NodeName
		nwiface.Spec.Subnet = attachment.Subnet
		nwiface.Spec.L2Network = attachment.L2Network
		nwiface.Spec.Address = attachment.Address
		nwiface.Spec.SecurityGroups = attachment.SecurityGroups
		nwiface.Spec.AllocationIdentity = workload.AllocationIdentity(pod)
		nwiface.Spec.RetainWhile = workload.RetainReference(pod)
		if attachment.Interface == juneauv1alpha1.PodPrimaryInterfaceName {
			nwiface.Spec.DNSNames = append([]string(nil), dnsNames...)
		} else {
			nwiface.Spec.DNSNames = nil
		}

		return ctrl.SetControllerReference(pod, nwiface, r.Scheme)
	})
	return err
}

// deleteNetworkInterfaces removes every NetworkInterface of this pod
// instance whose interface name is not in keep. A nil keep set removes all
// of them, which is what a finished pod wants.
func (r *PodReconciler) deleteNetworkInterfaces(ctx context.Context, pod *corev1.Pod, keep map[string]struct{}) error {
	var list juneauv1alpha1.NetworkInterfaceList
	if err := r.List(ctx, &list, client.InNamespace(pod.Namespace), client.MatchingFields{
		networkInterfacePodUIDIndex: string(pod.UID),
	}); err != nil {
		return err
	}

	for i := range list.Items {
		nwiface := &list.Items[i]
		if _, wanted := keep[nwiface.Spec.PodRef.Interface]; wanted {
			continue
		}
		if err := r.Delete(ctx, nwiface); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("delete NetworkInterface %s/%s: %w", nwiface.Namespace, nwiface.Name, err)
		}
	}
	return nil
}

// networkInterfaceNameForPod is the name the Pod controller gives the
// NetworkInterface of one pod NIC.
func networkInterfaceNameForPod(podName, ifName string) string {
	return podName + "." + ifName
}

// SetupWithManager sets up the controller with the Manager.
func (r *PodReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := indexNetworkInterfaceByPodUID(context.Background(), mgr.GetFieldIndexer()); err != nil {
		return err
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		Named("pod").
		Complete(r)
}

func indexNetworkInterfaceByPodUID(ctx context.Context, indexer client.FieldIndexer) error {
	if err := indexer.IndexField(
		ctx,
		&juneauv1alpha1.NetworkInterface{},
		networkInterfacePodUIDIndex,
		func(obj client.Object) []string {
			nwiface := obj.(*juneauv1alpha1.NetworkInterface)
			if nwiface.Spec.PodRef.UID == "" {
				return nil
			}
			return []string{nwiface.Spec.PodRef.UID}
		},
	); err != nil {
		return fmt.Errorf("failed to set up field indexer for NetworkInterface.%s: %w", networkInterfacePodUIDIndex, err)
	}
	return nil
}
