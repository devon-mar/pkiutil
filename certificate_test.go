package pkiutil

import (
	"bytes"
	"os"
	"path"
	"slices"
	"testing"
)

func TestParseMarshalCertificates(t *testing.T) {
	files := []string{
		"isrg-root-x2.pem",
	}

	for _, file := range files {
		t.Run(file, func(t *testing.T) {
			b, err := os.ReadFile(path.Join("testdata", file))
			if err != nil {
				t.Fatalf("unexpected error reading file: %v", err)
			}

			cert, err := ParseCertificate(b)
			if err != nil {
				t.Fatalf("error unmarshalling: %v", err)
			}

			haveBytes, err := MarshalCertificate(cert)
			if err != nil {
				t.Fatalf("error marshalling: %v", err)
			}

			if !slices.Equal(b, haveBytes) {
				t.Errorf("expected MarshalCertificate output to be %q, got %q", b, haveBytes)
			}

			var buff bytes.Buffer
			err = MarshalCertificateW(&buff, cert)
			if err != nil {
				t.Fatalf("error marshalling to bytes.Buffer: %v", err)
			}

			if !slices.Equal(b, buff.Bytes()) {
				t.Errorf("expected MarshalCertificateW output to be %q, got %q", b, buff.Bytes())
			}
		})
	}
}

func TestParseCertificates(t *testing.T) {
	tests := map[string]struct {
		in string
		// if 0, will be set to 10.
		limit int

		cns   []string
		error bool
	}{
		"single cert": {
			in:  "isrg-root-x2.pem",
			cns: []string{"CN=ISRG Root X2,O=Internet Security Research Group,C=US"},
		},
		"multiple": {
			in: "lets-encrypt-e1-chain.pem",

			// should return the first
			cns: []string{
				"CN=E1,O=Let's Encrypt,C=US",
				"CN=ISRG Root X2,O=Internet Security Research Group,C=US",
			},
		},
		"multiple limit 1": {
			in: "lets-encrypt-e1-chain.pem",

			// should return the first
			cns: []string{
				"CN=E1,O=Let's Encrypt,C=US",
			},
			limit: 1,
		},
		"empty file": {
			in:    "empty",
			error: true,
		},
		"der": {
			in:    "isrg-root-x2.der",
			error: true,
		},
		"private key": {
			in:    "ec256.key",
			error: true,
		},
		"corrupted cert": {
			in:    "isrg-root-x2-corrupted.pem",
			error: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// set defaults
			if tc.limit == 0 {
				tc.limit = 10
			}

			b, err := os.ReadFile(path.Join("testdata", tc.in))
			if err != nil {
				t.Errorf("unexpected error reading input file: %v", err)
				return
			}

			certs, err := ParseCertificates(b, tc.limit)
			if err == nil && tc.error {
				t.Error("expected an error but got nil")
			} else if err != nil && !tc.error {
				t.Fatalf("expected no error but got %v", err)
			} else if err != nil {
				return
			}

			have := []string{}
			for _, c := range certs {
				have = append(have, c.Subject.String())
			}

			if !slices.Equal(tc.cns, have) {
				t.Errorf("expected subject %#v, got %#v", tc.cns, have)
			}
		})
	}
}

func TestParseCertificate(t *testing.T) {
	tests := map[string]struct {
		in string

		cn    string
		error bool
	}{
		"multiple certs": {
			in: "lets-encrypt-e1-chain.pem",

			// should return the first
			cn: "CN=E1,O=Let's Encrypt,C=US",
		},
		"empty file": {
			in:    "empty",
			error: true,
		},
		"der": {
			in:    "isrg-root-x2.der",
			error: true,
		},
		"private key": {
			in:    "ec256.key",
			error: true,
		},
		"corrupted cert": {
			in:    "isrg-root-x2-corrupted.pem",
			error: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			b, err := os.ReadFile(path.Join("testdata", tc.in))
			if err != nil {
				t.Fatalf("unexpected error reading input file: %v", err)
			}

			have, err := ParseCertificate(b)
			if err == nil && tc.error {
				t.Error("expected an error but got nil")
			} else if err != nil && !tc.error {
				t.Fatalf("expected no error but got %v", err)
			} else if err != nil {
				return
			}

			if haveSubject := have.Subject.String(); tc.cn != haveSubject {
				t.Errorf("expected cn %q, got %q", tc.cn, have.Subject)
			}
		})
	}
}
