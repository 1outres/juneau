package server

import (
	"context"

	"github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/daemon/internal/daemon/kubeclient"
	"github.com/1outres/juneau/daemon/pkg/juneaupb"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type IPAMServer struct {
	juneaupb.UnimplementedIPAMServer
	kubeclient kubeclient.Client
}

func NewIPAMServer(kubeclient kubeclient.Client) *IPAMServer {
	return &IPAMServer{
		kubeclient: kubeclient,
	}
}

func (s *IPAMServer) Allocate(ctx context.Context, req *juneaupb.AllocateRequest) (*juneaupb.AllocateResponse, error) {
	pod, err := s.kubeclient.Corev1().Pod(req.Id.PodNamespace).Get(ctx, req.Id.PodName, metav1.GetOptions{})
	if err != nil {
		zap.S().Errorf("failed to get pod %s/%s: %v", req.Id.PodNamespace, req.Id.PodName, err)
		return &juneaupb.AllocateResponse{
			Error: &juneaupb.Error{
				Message: "failed to get pod",
			},
		}, nil
	}

	if req.Id.PodUid != "" && string(pod.UID) != req.Id.PodUid {
		zap.S().Infof("pod UID mismatch: expected %s, got %s", req.Id.PodUid, pod.UID)
		return &juneaupb.AllocateResponse{
			Error: &juneaupb.Error{
				Message: "pod UID mismatch",
			},
		}, nil
	}


	address := &v1alpha1.Address{
		ObjectMeta: metav1.ObjectMeta{
			Name: req.Id.IfName+"."+pod.Name,
		},
		Spec: v1alpha1.AddressSpec{
			MAC: req.MacAddress,
		},
	}

	subnet, ok := pod.Annotations["juneau.loutres.me/subnet"]
	if !ok {
		subnet = "default"
	}
	address.Spec.Subnet = subnet

	staticIp, ok := pod.Annotations["juneau.loutres.me/static-ip"]
	if ok {
		address.Spec.Address = staticIp
	}

	if _, err := s.kubeclient.Juneauv1alpha1().Address(pod.Namespace).Create(ctx,address, metav1.CreateOptions{}); err != nil {
		zap.S().Errorf("failed to create address %s/%s: %v", address.Namespace, address.Name, err)
		return &juneaupb.AllocateResponse{
			Error: &juneaupb.Error{
				Message: "failed to create address",
			},
		}, nil
	}

	// address.Status.Addressが設定されるまで待つ(30秒でタイムアウト)
	informerFactory := s.kubeclient.JuneauSharedInformerFactory()

	return nil, nil
}
