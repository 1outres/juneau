// webhookcertjob issues/renews the webhook TLS certificate via the CSR API and writes it into a Secret.
// It is intended to run as a Job/CronJob with hostNetwork enabled; SANs are populated with all node IPs and localhost.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	typedcertv1 "k8s.io/client-go/kubernetes/typed/certificates/v1"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	_ "k8s.io/client-go/plugin/pkg/client/auth" // auth providers
	"k8s.io/client-go/rest"
)

const (
	secretTypeTLS       = "kubernetes.io/tls"
	defaultSignerName   = "kubernetes.io/legacy-unknown"
	defaultCSRWait      = 2 * time.Minute
	defaultPollInterval = 2 * time.Second
)

func main() {
	var (
		secretName    string
		namespace     string
		commonName    string
		csrName       string
		thresholdDays int
		signerName    string
	)

	flag.StringVar(&secretName, "secret-name", "juneau-webhook-certs", "Name of the TLS Secret to create/update")
	flag.StringVar(&namespace, "namespace", os.Getenv("POD_NAMESPACE"), "Namespace of the Secret (default from POD_NAMESPACE env)")
	flag.StringVar(&commonName, "common-name", "webhook-server", "CommonName for the certificate subject")
	flag.StringVar(&csrName, "csr-name", "", "Name of the CSR object (auto-generated if empty)")
	flag.IntVar(&thresholdDays, "renew-before-days", 30, "If existing certificate expires in fewer days, renew it")
	flag.StringVar(&signerName, "signer-name", defaultSignerName, "SignerName used for the CSR")
	flag.Parse()

	if namespace == "" {
		namespace = "default"
	}

	ctx := context.Background()

	cfg, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("failed to get in-cluster config: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Fatalf("failed to create clientset: %v", err)
	}

	secretClient := clientset.CoreV1().Secrets(namespace)

	// Skip issuance if the existing cert is still valid beyond the threshold.
	if shouldSkip, err := existingCertValid(ctx, secretClient, secretName, thresholdDays); err == nil && shouldSkip {
		log.Printf("existing certificate in secret %s/%s is still valid, skipping issuance", namespace, secretName)
		return
	} else if err != nil && !errors.Is(err, errCertMissing) {
		log.Fatalf("failed to check existing certificate: %v", err)
	}

	nodeIPs, err := getNodeIPs(ctx, clientset)
	if err != nil {
		log.Fatalf("failed to list node IPs: %v", err)
	}

	// Always include localhost to allow loopback termination.
	nodeIPs = appendUniqueIP(nodeIPs, net.ParseIP("127.0.0.1"))
	if ip := net.ParseIP("::1"); ip != nil {
		nodeIPs = appendUniqueIP(nodeIPs, ip)
	}

	privateKey, csrDER, err := buildCSR(commonName, nodeIPs)
	if err != nil {
		log.Fatalf("failed to build CSR: %v", err)
	}

	if csrName == "" {
		csrName = fmt.Sprintf("webhook-cert-%d", time.Now().UnixNano())
	}

	csrClient := clientset.CertificatesV1().CertificateSigningRequests()

	if err := createOrReplaceCSR(ctx, csrClient, csrName, signerName, csrDER); err != nil {
		log.Fatalf("failed to create CSR: %v", err)
	}

	if err := approveCSR(ctx, csrClient, csrName); err != nil {
		log.Fatalf("failed to approve CSR: %v", err)
	}

	certPEM, err := waitForCertificate(ctx, csrClient, csrName)
	if err != nil {
		log.Fatalf("failed to get issued certificate: %v", err)
	}

	tlsKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	if err := upsertTLSSecret(ctx, secretClient, secretName, tlsKeyPEM, certPEM); err != nil {
		log.Fatalf("failed to upsert secret: %v", err)
	}

	log.Printf("certificate issued and stored in secret %s/%s", namespace, secretName)
}

var errCertMissing = errors.New("certificate missing")

func existingCertValid(ctx context.Context, secretClient typedcorev1.SecretInterface, secretName string, thresholdDays int) (bool, error) {
	secret, err := secretClient.Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return false, err
	}

	certPEM := secret.Data[corev1.TLSCertKey]
	if len(certPEM) == 0 {
		return false, errCertMissing
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false, fmt.Errorf("failed to decode existing certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse existing certificate: %w", err)
	}

	renewBefore := time.Duration(thresholdDays) * 24 * time.Hour
	if time.Until(cert.NotAfter) > renewBefore {
		return true, nil
	}

	return false, nil
}

func getNodeIPs(ctx context.Context, clientset *kubernetes.Clientset) ([]net.IP, error) {
	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	seen := map[string]struct{}{}
	var ips []net.IP
	for _, n := range nodes.Items {
		for _, addr := range n.Status.Addresses {
			if addr.Type != corev1.NodeInternalIP && addr.Type != corev1.NodeExternalIP {
				continue
			}
			ip := net.ParseIP(addr.Address)
			if ip == nil {
				continue
			}
			key := ip.String()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			ips = append(ips, ip)
		}
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no node IPs found")
	}

	return ips, nil
}

func appendUniqueIP(list []net.IP, ip net.IP) []net.IP {
	if ip == nil {
		return list
	}
	for _, existing := range list {
		if existing.Equal(ip) {
			return list
		}
	}
	return append(list, ip)
}

func buildCSR(commonName string, ips []net.IP) (*rsa.PrivateKey, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}

	req := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		IPAddresses: ips,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, req, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}

	return key, csrDER, nil
}

func createOrReplaceCSR(ctx context.Context, csrClient typedcertv1.CertificateSigningRequestInterface, name, signerName string, csrDER []byte) error {
	// Clean up any previous CSR with the same name.
	_ = csrClient.Delete(ctx, name, metav1.DeleteOptions{})

	pemCSR := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	csr := &certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "webhook-cert-job",
				"app.kubernetes.io/component":  "certificate",
				"app.kubernetes.io/part-of":    "juneau",
				"certjob.loutres.me/generated": "true",
			},
		},
		Spec: certificatesv1.CertificateSigningRequestSpec{
			Request:    pemCSR,
			SignerName: signerName,
			Usages: []certificatesv1.KeyUsage{
				certificatesv1.UsageDigitalSignature,
				certificatesv1.UsageKeyEncipherment,
				certificatesv1.UsageServerAuth,
			},
		},
	}

	_, err := csrClient.Create(ctx, csr, metav1.CreateOptions{})
	return err
}

func approveCSR(ctx context.Context, csrClient typedcertv1.CertificateSigningRequestInterface, name string) error {
	now := metav1.Now()
	approval := &certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Status: certificatesv1.CertificateSigningRequestStatus{
			Conditions: []certificatesv1.CertificateSigningRequestCondition{
				{
					Type:           certificatesv1.CertificateApproved,
					Status:         corev1.ConditionTrue,
					Reason:         "CertJobApproved",
					Message:        "Approved by webhook cert job",
					LastUpdateTime: now,
				},
			},
		},
	}

	_, err := csrClient.UpdateApproval(ctx, name, approval, metav1.UpdateOptions{})
	return err
}

func waitForCertificate(ctx context.Context, csrClient typedcertv1.CertificateSigningRequestInterface, name string) ([]byte, error) {
	var cert []byte
	err := wait.PollUntilContextTimeout(ctx, defaultPollInterval, defaultCSRWait, true, func(ctx context.Context) (bool, error) {
		csr, err := csrClient.Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if len(csr.Status.Certificate) == 0 {
			return false, nil
		}
		cert = csr.Status.Certificate
		return true, nil
	})
	return cert, err
}

func upsertTLSSecret(ctx context.Context, secretClient typedcorev1.SecretInterface, secretName string, keyPEM, certPEM []byte) error {
	secret, err := secretClient.Get(ctx, secretName, metav1.GetOptions{})
	if err == nil {
		secret.Type = secretTypeTLS
		if secret.Data == nil {
			secret.Data = map[string][]byte{}
		}
		secret.Data[corev1.TLSCertKey] = certPEM
		secret.Data[corev1.TLSPrivateKeyKey] = keyPEM
		_, err = secretClient.Update(ctx, secret, metav1.UpdateOptions{})
		return err
	}

	newSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: secretName,
		},
		Type: secretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM,
			corev1.TLSPrivateKeyKey: keyPEM,
		},
	}
	_, err = secretClient.Create(ctx, newSecret, metav1.CreateOptions{})
	return err
}
