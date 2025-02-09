package pkiutil

import (
	"bytes"
	"crypto"
	"os"
	"path"
	"slices"
	"testing"
)

func TestParseMarshalPrivateKey(t *testing.T) {
	files := []string{
		"rsa2048.key",
		"rsa4096.key",
		"rsa8192.key",
		"ec224-pkcs8.key",
		"ec256-pkcs8.key",
		"ec384-pkcs8.key",
		"ec521-pkcs8.key",
	}

	for _, file := range files {
		t.Run(file, func(t *testing.T) {
			expected, err := os.ReadFile(path.Join("testdata", file))
			if err != nil {
				t.Fatalf("unexpected error reading file: %v", err)
			}

			pk, err := ParsePrivateKey(expected)
			if err != nil {
				t.Fatalf("unexpected error unmarshalling: %v", err)
			}

			var buff bytes.Buffer
			err = MarshalPrivateKeyW(&buff, pk)
			if err != nil {
				t.Fatalf("error marshalling to bytes.Buffer: %v", err)
			}

			if !slices.Equal(expected, buff.Bytes()) {
				t.Errorf("expected MarshalPrivateKeyW output to be %q, got %q", expected, buff.Bytes())
			}

			b, err := MarshalPrivateKey(pk)
			if err != nil {
				t.Fatalf("expected no error but got: %v", err)
			}

			if !slices.Equal(expected, b) {
				t.Errorf("expected MarshalPrivateKey output to be %q, got %q", expected, b)
			}
		})
	}
}

func TestMarshalPrivateKeyInvalidKeyType(t *testing.T) {
	var key string
	_, err := MarshalPrivateKey(key)
	if err == nil {
		t.Errorf("expected an error but got nil")
	}

	var buff bytes.Buffer
	err = MarshalPrivateKeyW(&buff, key)
	if err == nil {
		t.Errorf("expected an error but got nil")
	}
}

func TestParsePrivateKeyNotPKCS8(t *testing.T) {
	// Map of non-pkcs8 version to pkcs8 version
	files := map[string]string{
		"rsa2048-pkcs1.key": "rsa2048.key",
		"ec256.key":         "ec256-pkcs8.key",
	}

	for nonPkcs8File, pkcs8File := range files {
		t.Run(nonPkcs8File, func(t *testing.T) {
			nonPkcs8Bytes, err := os.ReadFile(path.Join("testdata", nonPkcs8File))
			if err != nil {
				t.Fatalf("unexpected error reading input non-pkcs8 file: %v", err)
			}

			pkcs8Bytes, err := os.ReadFile(path.Join("testdata", pkcs8File))
			if err != nil {
				t.Fatalf("unexpected error reading input pkcs8 file: %v", err)
			}

			nonPkcs8Key, err := ParsePrivateKey(nonPkcs8Bytes)
			if err != nil {
				t.Fatalf("expected no error unmarhsalling non-pkcs8 key but got %v", err)
			}

			pkcs8Key, err := ParsePrivateKey(pkcs8Bytes)
			if err != nil {
				t.Fatalf("expected no error unmarhsalling pkcs8 key but got %v", err)
			}

			type hasEqual interface {
				Equal(crypto.PrivateKey) bool
			}

			pkcs8KeyEqual := pkcs8Key.(hasEqual)

			if !pkcs8KeyEqual.Equal(nonPkcs8Key) {
				t.Errorf("expected private keys to be qual")
			}
		})
	}
}

func TestParseMarshalPrivateKeyErrors(t *testing.T) {
	files := map[string]string{
		"certificate": "isrg-root-x2.pem",
		"corrupted":   "ec224-corrupted.key",
		"empty":       "empty",
	}

	for name, file := range files {
		t.Run(name, func(t *testing.T) {
			b, err := os.ReadFile(path.Join("testdata", file))
			if err != nil {
				t.Fatalf("unexpected error reading input file: %v", err)
			}

			_, err = ParsePrivateKey(b)
			if err == nil {
				t.Errorf("expected an error but got nil")
			}
		})
	}
}
