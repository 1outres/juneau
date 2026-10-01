package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestEnsureServerCertRenewsWhenNodeIPChanges(t *testing.T) {
	ctx := context.Background()
	secrets := fake.NewSimpleClientset().CoreV1().Secrets("test")
	caCert, caKey, caPEM, err := ensureCA(ctx, secrets, "ca", 10)
	if err != nil {
		t.Fatal(err)
	}
	ips := []net.IP{net.ParseIP("172.18.0.4")}
	if err := ensureServerCert(ctx, secrets, "server", "webhook-server", ips, 30, 90, caCert, caKey, caPEM); err != nil {
		t.Fatal(err)
	}
	original, err := secrets.Get(ctx, "server", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ips = append(ips, net.ParseIP("172.18.0.5"))
	if err := ensureServerCert(ctx, secrets, "server", "webhook-server", ips, 30, 90, caCert, caKey, caPEM); err != nil {
		t.Fatal(err)
	}
	updated, err := secrets.Get(ctx, "server", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if string(updated.Data[corev1.TLSCertKey]) == string(original.Data[corev1.TLSCertKey]) {
		t.Fatal("server certificate was not renewed when a node IP was added")
	}
	block, _ := pem.Decode(updated.Data[corev1.TLSCertKey])
	if block == nil {
		t.Fatal("server certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range ips {
		if err := cert.VerifyHostname(ip.String()); err != nil {
			t.Errorf("server certificate does not cover %s: %v", ip, err)
		}
	}
	if err := ensureServerCert(ctx, secrets, "server", "webhook-server", ips, 30, 90, caCert, caKey, caPEM); err != nil {
		t.Fatal(err)
	}
	reused, err := secrets.Get(ctx, "server", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if string(reused.Data[corev1.TLSCertKey]) != string(updated.Data[corev1.TLSCertKey]) {
		t.Fatal("valid server certificate was renewed without a change")
	}
}
