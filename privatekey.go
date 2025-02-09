package pkiutil

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
)

const (
	pemBlockPrivateKey1  = "RSA PRIVATE KEY"
	pemBlockPrivateKey8  = "PRIVATE KEY"
	pemBlockECPrivateKey = "EC PRIVATE KEY"
)

// Parse a PEM formatted private key.
func ParsePrivateKey(b []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(b)

	if block == nil {
		return nil, fmt.Errorf("no PEM data found")
	}

	var c crypto.PrivateKey
	var err error

	switch block.Type {
	case pemBlockPrivateKey8:
		c, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case pemBlockPrivateKey1:
		c, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case pemBlockECPrivateKey:
		c, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unexpected block type for private key: %s", block.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	return c, nil
}

// Convert a private key to PEM encoded PKCS #8 written to out.
func MarshalPrivateKeyW(out io.Writer, pk crypto.PrivateKey) error {
	b, err := x509.MarshalPKCS8PrivateKey(pk)
	if err != nil {
		return fmt.Errorf("marshal pkcs8: %w", err)
	}

	block := &pem.Block{
		Type:  pemBlockPrivateKey8,
		Bytes: b,
	}

	return pem.Encode(out, block)
}

// Convert a private key to PEM encoded PKCS #8.
func MarshalPrivateKey(pk crypto.PrivateKey) ([]byte, error) {
	var buf bytes.Buffer

	if err := MarshalPrivateKeyW(&buf, pk); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
