// webhookcertjob generates or reuses a dedicated CA, signs a webhook-serving certificate with it,
// and writes the server cert/key (and CA cert) into a Secret for the webhook Pod to mount.
// It is intended to run as a Job/CronJob with hostNetwork; SANs are populated with all node IPs and localhost.
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
	"math/big"
	"net"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	_ "k8s.io/client-go/plugin/pkg/client/auth" // auth providers
	"k8s.io/client-go/rest"
)

const (
	secretTypeTLS       = "kubernetes.io/tls"
	defaultServerDays   = 90
	defaultCAValidYears = 10
)

func main() {
	var (
		serverSecret string
		caSecret     string
		namespace    string
		commonName   string
		renewBefore  int
		serverDays   int
		caYears      int
	)

	flag.StringVar(&serverSecret, "secret-name", "webhook-certs", "Name of the TLS Secret to create/update for the webhook server")
	flag.StringVar(&caSecret, "ca-secret-name", "webhook-ca", "Name of the Secret that stores the CA cert/key (created if absent)")
	flag.StringVar(&namespace, "namespace", os.Getenv("POD_NAMESPACE"), "Namespace for the Secrets (default from POD_NAMESPACE env)")
	flag.StringVar(&commonName, "common-name", "webhook-server", "CommonName for the server certificate")
	flag.IntVar(&renewBefore, "renew-before-days", 30, "If server certificate expires sooner than this, issue a new one")
	flag.IntVar(&serverDays, "server-valid-days", defaultServerDays, "Validity (days) for the server certificate")
	flag.IntVar(&caYears, "ca-valid-years", defaultCAValidYears, "Validity (years) for the CA certificate")
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

	caCert, caKey, caPEM, err := ensureCA(ctx, secretClient, caSecret, caYears)
	if err != nil {
		log.Fatalf("failed to ensure CA: %v", err)
	}

	nodeIPs, err := getNodeIPs(ctx, clientset)
	if err != nil {
		log.Fatalf("failed to list node IPs: %v", err)
	}
	nodeIPs = appendUniqueIP(nodeIPs, net.ParseIP("127.0.0.1"))
	if ip := net.ParseIP("::1"); ip != nil {
		nodeIPs = appendUniqueIP(nodeIPs, ip)
	}

	if err := ensureServerCert(ctx, secretClient, serverSecret, commonName, nodeIPs, renewBefore, serverDays, caCert, caKey, caPEM); err != nil {
		log.Fatalf("failed to ensure server certificate: %v", err)
	}

	log.Printf("server certificate ensured in secret %s/%s", namespace, serverSecret)
}

func ensureCA(ctx context.Context, secrets typedcorev1.SecretInterface, caSecret string, validYears int) (*x509.Certificate, *rsa.PrivateKey, []byte, error) {
	secret, err := secrets.Get(ctx, caSecret, metav1.GetOptions{})
	if err == nil {
		cert, key, caPEM, parseErr := parseCertAndKey(secret)
		if parseErr != nil {
			log.Printf("failed to parse existing CA secret, regenerating: %v", parseErr)
		} else if time.Until(cert.NotAfter) > 30*24*time.Hour {
			return cert, key, caPEM, nil
		}
	}

	// Generate new CA
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate CA key: %w", err)
	}

	now := time.Now().UTC()
	caTmpl := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: "webhook-ca"},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(time.Duration(validYears) * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create CA cert: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse CA cert: %w", err)
	}

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	newSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: caSecret,
			Labels: map[string]string{
				"app.kubernetes.io/name":    "webhook-cert-job",
				"app.kubernetes.io/part-of": "juneau",
			},
		},
		Type: secretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       caPEM,
			corev1.TLSPrivateKeyKey: keyPEM,
		},
	}

	_, err = secrets.Update(ctx, newSecret, metav1.UpdateOptions{})
	if kerrors.IsNotFound(err) {
		_, err = secrets.Create(ctx, newSecret, metav1.CreateOptions{})
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("store CA secret: %w", err)
	}

	return cert, key, caPEM, nil
}

func ensureServerCert(
	ctx context.Context,
	secrets typedcorev1.SecretInterface,
	secretName, commonName string,
	ips []net.IP,
	renewBeforeDays int,
	validDays int,
	caCert *x509.Certificate,
	caKey *rsa.PrivateKey,
	caPEM []byte,
) error {
	existing, err := secrets.Get(ctx, secretName, metav1.GetOptions{})
	if err == nil {
		cert, _, _, parseErr := parseCertAndKey(existing)
		if parseErr == nil {
			pool := x509.NewCertPool()
			pool.AddCert(caCert)
			if time.Until(cert.NotAfter) > time.Duration(renewBeforeDays)*24*time.Hour {
				_, verr := cert.Verify(x509.VerifyOptions{
					Roots:     pool,
					KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				})
				if verr == nil {
					log.Printf("existing server cert still valid, skipping issuance")
					return nil
				}
				log.Printf("existing server cert failed CA verification: %v", verr)
			}
		} else {
			log.Printf("failed to parse existing server cert, will re-issue: %v", parseErr)
		}
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate server key: %w", err)
	}

	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(time.Duration(validDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           ips,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create server cert: %w", err)
	}

	serverPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	newSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: secretName,
			Labels: map[string]string{
				"app.kubernetes.io/name":    "webhook-cert-job",
				"app.kubernetes.io/part-of": "juneau",
			},
		},
		Type: secretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       serverPEM,
			corev1.TLSPrivateKeyKey: keyPEM,
			"ca.crt":                caPEM,
		},
	}

	_, err = secrets.Update(ctx, newSecret, metav1.UpdateOptions{})
	if kerrors.IsNotFound(err) {
		_, err = secrets.Create(ctx, newSecret, metav1.CreateOptions{})
	}
	if err != nil {
		return fmt.Errorf("store server secret: %w", err)
	}

	return nil
}

func parseCertAndKey(secret *corev1.Secret) (*x509.Certificate, *rsa.PrivateKey, []byte, error) {
	certPEM := secret.Data[corev1.TLSCertKey]
	keyPEM := secret.Data[corev1.TLSPrivateKeyKey]
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return nil, nil, nil, errors.New("cert or key missing")
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, nil, errors.New("failed to decode cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse cert: %w", err)
	}

	key, err := parseRSAPrivateKey(keyPEM)
	if err != nil {
		return nil, nil, nil, err
	}

	return cert, key, certPEM, nil
}

func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to decode key PEM")
	}

	if block.Type == "RSA PRIVATE KEY" {
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("key is not RSA")
	}
	return rsaKey, nil
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

func randomSerial() *big.Int {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, max)
	if err != nil {
		return big.NewInt(time.Now().UnixNano())
	}
	return serial
}
