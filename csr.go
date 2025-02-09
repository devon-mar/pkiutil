package pkiutil

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
)

const (
	pemBlockCSR = "CERTIFICATE REQUEST"
)

func MarshalCertificateRequestW(out io.Writer, csr []byte) error {
	block := &pem.Block{
		Type:    pemBlockCSR,
		Headers: nil,
		Bytes:   csr,
	}

	return pem.Encode(out, block)
}

// Marshal the given certificate request to PEM format.
func MarshalCertificateRequest(csr []byte) ([]byte, error) {
	var buf bytes.Buffer

	if err := MarshalCertificateRequestW(&buf, csr); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func ParseCertificateRequest(b []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("no PEM data found.")
	}

	if block.Type != pemBlockCSR {
		return nil, fmt.Errorf("unexpected block type: %s", block.Type)
	}

	c, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	return c, nil
}
