package server

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/daemon/internal/daemon/kubeclient"
	"github.com/1outres/juneau/daemon/pkg/juneaupb"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
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
			Success: false,
			Error: &juneaupb.Error{
				Message: "failed to get pod",
			},
		}, nil
	}

	if req.Id.PodUid != "" && string(pod.UID) != req.Id.PodUid {
		zap.S().Infof("pod UID mismatch: expected %s, got %s", req.Id.PodUid, pod.UID)
		return &juneaupb.AllocateResponse{
			Success: false,
			Error: &juneaupb.Error{
				Message: "pod UID mismatch",
			},
		}, nil
	}

	subnetName, ok := pod.Annotations["juneau.loutres.me/subnet"]
	if !ok {
		subnetName = "default"
	}

	subnet, err := s.kubeclient.Juneauv1alpha1().Subnet().Get(ctx, subnetName, metav1.GetOptions{})
	if err != nil {
		zap.S().Errorf("failed to get subnet %s: %v", subnetName, err)
		return &juneaupb.AllocateResponse{
			Success: false,
			Error: &juneaupb.Error{
				Message: "failed to get subnet",
			},
		}, nil
	}

	address := &v1alpha1.Address{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: pod.Namespace,
			Name:      req.Id.IfName + "." + pod.Name,
		},
		Spec: v1alpha1.AddressSpec{
			MAC:    req.MacAddress,
			Subnet: subnet.Name,
		},
	}

	staticIp, ok := pod.Annotations["juneau.loutres.me/static-ip"]
	if ok {
		address.Spec.Address = staticIp
	}

	if _, err := s.kubeclient.Juneauv1alpha1().Address(pod.Namespace).Create(ctx, address, metav1.CreateOptions{}); err != nil && !errors.IsAlreadyExists(err) {
		zap.S().Errorf("failed to create address %s/%s: %v", address.Namespace, address.Name, err)
		return &juneaupb.AllocateResponse{
			Success: false,
			Error: &juneaupb.Error{
				Message: "failed to create address",
			},
		}, nil
	}

	waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	addrInformer := s.kubeclient.JuneauSharedInformerFactory().Api().V1alpha1().Addresses().Informer()
	addrLister := s.kubeclient.JuneauSharedInformerFactory().Api().V1alpha1().Addresses().Lister()

	keyNS := pod.Namespace
	keyName := address.Name

	ipCh := make(chan string, 1)

	notifyIfReady := func(obj any) {
		a, ok := obj.(*v1alpha1.Address)
		if !ok {
			return
		}
		if a.Namespace != keyNS || a.Name != keyName {
			return
		}
		if ip := a.Status.Address; ip != "" {
			ipCh <- ip
		}
	}

	reg, err := addrInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    notifyIfReady,
			UpdateFunc: func(oldObj, newObj any) { notifyIfReady(newObj) },
		},
		0,
	)
	if err != nil {
		zap.S().Errorf("failed to add event handler: %v", err)
		return &juneaupb.AllocateResponse{
			Success: false,
			Error:   &juneaupb.Error{Message: "failed to add event handler"},
		}, nil
	}
	defer func() {
		_ = addrInformer.RemoveEventHandler(reg)
	}()

	if got, err := addrLister.Addresses(keyNS).Get(keyName); err == nil {
		if ip := got.Status.Address; ip != "" {
			ipCh <- ip
		}
	}

	select {
	case <-waitCtx.Done():
		zap.S().Warnf("waiting address %s/%s status.address timed out", keyNS, keyName)
		return &juneaupb.AllocateResponse{
			Success: false,
			Error:   &juneaupb.Error{Message: "allocation timed out"},
		}, nil
	case ip := <-ipCh:
		_, ipnet, err := net.ParseCIDR(subnet.Spec.CIDR)
		if err != nil {
			zap.S().Errorf("failed to parse subnet CIDR %s: %v", subnet.Spec.CIDR, err)
			return &juneaupb.AllocateResponse{
				Success: false,
				Error:   &juneaupb.Error{Message: "failed to parse subnet CIDR"},
			}, nil
		}
		ones, _ := ipnet.Mask.Size()

		return &juneaupb.AllocateResponse{
			Success: true,
			IpAssignment: &juneaupb.IPAssignment{
				Ipv4: &juneaupb.IPConfig{
					AddressCidr: fmt.Sprintf("%s/%d", ip, ones),
					Gateway:     subnet.Status.Gateway,
				},
			},
		}, nil
	}
}
