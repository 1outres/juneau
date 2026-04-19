package v1alpha1

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/controller/internal/bootstrap"
)

var (
	webhookCfg       *rest.Config
	webhookTestEnv   *envtest.Environment
	webhookK8sClient client.Client
	webhookCtx       context.Context
	webhookCancel    context.CancelFunc
	webhookMgrDone   chan error
)

func TestWebhooks(t *testing.T) {
	RegisterFailHandler(Fail)
	SetDefaultEventuallyTimeout(10 * time.Second)
	RunSpecs(t, "Webhook Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	webhookCtx, webhookCancel = context.WithCancel(context.Background())

	scheme := runtime.NewScheme()
	Expect(clientgoscheme.AddToScheme(scheme)).To(Succeed())
	Expect(juneauv1alpha1.AddToScheme(scheme)).To(Succeed())

	webhookTestEnv = &envtest.Environment{
		CRDDirectoryPaths: []string{filepath.Join("..", "..", "..", "config", "crd", "bases")},
		WebhookInstallOptions: envtest.WebhookInstallOptions{
			Paths: []string{filepath.Join("..", "..", "..", "config", "webhook")},
		},
		ErrorIfCRDPathMissing: true,
	}

	if getFirstFoundEnvTestBinaryDir() != "" {
		webhookTestEnv.BinaryAssetsDirectory = getFirstFoundEnvTestBinaryDir()
	}

	var err error
	webhookCfg, err = webhookTestEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(webhookCfg).NotTo(BeNil())

	webhookK8sClient, err = client.New(webhookCfg, client.Options{Scheme: scheme})
	Expect(err).NotTo(HaveOccurred())

	webhookOpts := webhookTestEnv.WebhookInstallOptions
	mgr, err := ctrl.NewManager(webhookCfg, ctrl.Options{
		Scheme: scheme,
		WebhookServer: webhook.NewServer(webhook.Options{
			Host:    webhookOpts.LocalServingHost,
			Port:    webhookOpts.LocalServingPort,
			CertDir: webhookOpts.LocalServingCertDir,
		}),
		LeaderElection: false,
		Metrics: metricsserver.Options{
			BindAddress: "0",
		},
	})
	Expect(err).NotTo(HaveOccurred())
	Expect(SetupVpcWebhookWithManager(mgr)).To(Succeed())
	Expect(SetupSubnetWebhookWithManager(mgr)).To(Succeed())
	Expect(SetupNetworkInterfaceWebhookWithManager(mgr)).To(Succeed())
	Expect(SetupNetworkEndpointWebhookWithManager(mgr)).To(Succeed())
	Expect(SetupIPLeaseWebhookWithManager(mgr)).To(Succeed())
	Expect(SetupRouteTableWebhookWithManager(mgr)).To(Succeed())
	Expect(SetupAllocationPoolWebhookWithManager(mgr)).To(Succeed())
	Expect(SetupAllocationClaimWebhookWithManager(mgr)).To(Succeed())

	webhookMgrDone = make(chan error, 1)
	go func() {
		webhookMgrDone <- mgr.Start(webhookCtx)
	}()
	Expect(mgr.GetCache().WaitForCacheSync(webhookCtx)).To(BeTrue())

	addr := fmt.Sprintf("%s:%d", webhookOpts.LocalServingHost, webhookOpts.LocalServingPort)
	dialer := &net.Dialer{Timeout: time.Second}
	Eventually(func() error {
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return err
		}
		return conn.Close()
	}).Should(Succeed())

	Expect(bootstrap.EnsureDefaults(webhookCtx, webhookK8sClient, logf.Log.WithName("bootstrap"), "10.16.0.0/16")).To(Succeed())
})

var _ = AfterSuite(func() {
	webhookCancel()
	if webhookMgrDone != nil {
		Expect(<-webhookMgrDone).To(Succeed())
	}
	Expect(webhookTestEnv.Stop()).To(Succeed())
})

func getFirstFoundEnvTestBinaryDir() string {
	basePath := filepath.Join("..", "..", "..", "bin", "k8s")
	entries, err := os.ReadDir(basePath)
	if err != nil {
		logf.Log.Error(err, "Failed to read directory", "path", basePath)
		return ""
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return filepath.Join(basePath, entry.Name())
		}
	}
	return ""
}
