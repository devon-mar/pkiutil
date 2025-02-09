package pkiutil

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
)

const (
	pemBlockCert = "CERTIFICATE"
)

// Parse a PEM formatted certificate.
func ParseCertificate(b []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("no PEM data found.")
	}

	if block.Type != pemBlockCert {
		return nil, fmt.Errorf("unexpected block type: %s", block.Type)
	}

	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ParseCertificate: %w", err)
	}

	return c, nil
}

// Parse concatenanted PEM certificates up to limit.
// An error is returned if 0 certificates are parsed.
func ParseCertificates(b []byte, limit int) ([]*x509.Certificate, error) {
	rest := b

	ret := []*x509.Certificate{}

	for i := 0; i < limit; i++ {
		var decoded *pem.Block
		decoded, rest = pem.Decode(rest)
		if decoded == nil {
			break
		} else if decoded.Type != pemBlockCert {
			return nil, fmt.Errorf("unexpected block type: %s", decoded.Type)
		}

		c, err := x509.ParseCertificate(decoded.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse %d: %w", i, err)
		}
		ret = append(ret, c)
	}

	if len(ret) == 0 {
		return nil, errors.New("no certs read")
	}

	return ret, nil
}

// Marshal the given certificate in PEM format to out.
func MarshalCertificateW(out io.Writer, c *x509.Certificate) error {
	block := &pem.Block{
		Type:  pemBlockCert,
		Bytes: c.Raw,
	}

	return pem.Encode(out, block)
}

// Marshal the given certificate in PEM format.
func MarshalCertificate(c *x509.Certificate) ([]byte, error) {
	var buf bytes.Buffer

	if err := MarshalCertificateW(&buf, c); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
