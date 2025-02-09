package pkiutil

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"path"
	"slices"
	"testing"
)

func TestMarshalCertificateRequest(t *testing.T) {
	wantPEM, err := os.ReadFile("testdata/rsa2048-test-csr.csr")
	if err != nil {
		t.Fatalf("unexpected error reading expected csr: %v", err)
	}

	keyBytes, err := os.ReadFile("testdata/rsa2048.key")
	if err != nil {
		t.Fatalf("unexpected error reading test key: %v", err)
	}

	key, err := ParsePrivateKey(keyBytes)
	if err != nil {
		t.Fatalf("unexpected error unmarshalling private key: %v", err)
	}

	reqTemplate := x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test"},
	}

	reqBytes, err := x509.CreateCertificateRequest(rand.Reader, &reqTemplate, key)
	if err != nil {
		t.Fatalf("unexpected error creating certificate request: %v", err)
	}

	havePEM, err := MarshalCertificateRequest(reqBytes)
	if err != nil {
		t.Fatalf("expected no error but got: %v", err)
	}

	if !slices.Equal(wantPEM, havePEM) {
		t.Errorf("expected pem contents %q, got %q", string(wantPEM), string(havePEM))
	}
}

func TestMarshalCertificateRequestW(t *testing.T) {
	t.Parallel()

	wantPEM, err := os.ReadFile("testdata/rsa2048-test-csr.csr")
	if err != nil {
		t.Fatalf("unexpected error reading expected csr: %v", err)
	}

	keyBytes, err := os.ReadFile("testdata/rsa2048.key")
	if err != nil {
		t.Fatalf("unexpected error reading test key: %v", err)
	}

	key, err := ParsePrivateKey(keyBytes)
	if err != nil {
		t.Fatalf("unexpected error unmarshalling private key: %v", err)
	}

	reqTemplate := x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test"},
	}

	reqBytes, err := x509.CreateCertificateRequest(rand.Reader, &reqTemplate, key)
	if err != nil {
		t.Fatalf("unexpected error creating certificate request: %v", err)
	}

	var buf bytes.Buffer
	err = MarshalCertificateRequestW(&buf, reqBytes)
	if err != nil {
		t.Fatalf("expected no error but got: %v", err)
	}

	if !slices.Equal(wantPEM, buf.Bytes()) {
		t.Errorf("expected pem contents %q, got %q", string(wantPEM), buf.String())
	}

	havePEM, err := MarshalCertificateRequest(reqBytes)
	if err != nil {
		t.Fatalf("expected no error but got: %v", err)
	}
	if !slices.Equal(wantPEM, havePEM) {
		t.Errorf("expected pem contents %q, got %q", string(wantPEM), buf.String())
	}
}

func TestParseCertificateRequestErrors(t *testing.T) {
	files := map[string]string{
		"certificate": "isrg-root-x2.pem",
		"empty":       "empty",
		"corrupted":   "rsa2048-test-csr-corrupted.csr",
	}

	for name, file := range files {
		t.Run(name, func(t *testing.T) {
			b, err := os.ReadFile(path.Join("testdata", file))
			if err != nil {
				t.Fatalf("unexpected error reading input file: %v", err)
			}

			_, err = ParseCertificateRequest(b)
			if err == nil {
				t.Errorf("expected an error but got nil")
			}
		})
	}
}

func TestParseCertificateRequest(t *testing.T) {
	csrBytes, err := os.ReadFile("testdata/rsa2048-test-csr.csr")
	if err != nil {
		t.Fatalf("unexpected error reading expected csr: %v", err)
	}

	csr, err := ParseCertificateRequest(csrBytes)
	if err != nil {
		t.Errorf("expected no error but got: %v", err)
	}

	const expectedCN = "test"
	if expectedCN != csr.Subject.CommonName {
		t.Errorf("expected CN %q, got %q", expectedCN, csr.Subject.CommonName)
	}
}
