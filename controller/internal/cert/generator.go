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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Generator handles self-signed certificate generation for webhooks
type Generator struct {
	CertDir  string
	CertName string
	KeyName  string
}

// NewGenerator creates a new certificate generator with default paths
func NewGenerator(certDir string) *Generator {
	return &Generator{
		CertDir:  certDir,
		CertName: "tls.crt",
		KeyName:  "tls.key",
	}
}

// GenerateSelfSignedCert generates a self-signed certificate for the webhook server
// dnsNames: List of DNS names to include in the certificate (e.g., service names)
// ipAddresses: List of IP addresses to include in the certificate (e.g., node IPs)
func (g *Generator) GenerateSelfSignedCert(dnsNames []string, ipAddresses []string) error {
	// Create cert directory if it doesn't exist
	if err := os.MkdirAll(g.CertDir, 0755); err != nil {
		return fmt.Errorf("failed to create cert directory: %w", err)
	}

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create certificate template
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // 1 year validity

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"juneau-controller"},
			CommonName:   "juneau-webhook",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}

	// Add IP addresses if provided
	for _, ipStr := range ipAddresses {
		if ip := net.ParseIP(ipStr); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	}

	// Create self-signed certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Write certificate to file
	certPath := filepath.Join(g.CertDir, g.CertName)
	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to create cert file: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("failed to write cert to file: %w", err)
	}

	// Write private key to file
	keyPath := filepath.Join(g.CertDir, g.KeyName)
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyOut.Close()

	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("failed to write key to file: %w", err)
	}

	return nil
}

// GetCertPaths returns the full paths to the certificate and key files
func (g *Generator) GetCertPaths() (certPath, keyPath string) {
	return filepath.Join(g.CertDir, g.CertName),
		filepath.Join(g.CertDir, g.KeyName)
}

// ReadCertificate reads the certificate from disk and returns its PEM-encoded bytes
func (g *Generator) ReadCertificate() ([]byte, error) {
	certPath := filepath.Join(g.CertDir, g.CertName)
	return os.ReadFile(certPath)
}
