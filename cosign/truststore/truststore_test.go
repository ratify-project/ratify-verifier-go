/*
Copyright The Ratify Authors.
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

package truststore

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"testing"
	"time"
)

func TestNewTrustStore(t *testing.T) {
	ts := NewTrustStore()

	if ts == nil {
		t.Fatal("expected non-nil TrustStore")
	}
}

func TestGetKey(t *testing.T) {
	ts := NewTrustStore()
	ctx := context.Background()

	// Generate a test key
	testKey := &rsa.PublicKey{N: big.NewInt(12345), E: 65537}
	ts.(*truststore).keys["testKey"] = testKey

	key, err := ts.GetKey(ctx, "testKey")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if key != testKey {
		t.Fatalf("expected key %v, got %v", testKey, key)
	}

	_, err = ts.GetKey(ctx, "nonExistentKey")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGetCertificate(t *testing.T) {
	ts := NewTrustStore()
	ctx := context.Background()

	// Generate a test certificate
	testCert := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	ts.(*truststore).certificates["testCert"] = testCert

	cert, err := ts.GetCertificate(ctx, "testCert")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cert != testCert {
		t.Fatalf("expected certificate %v, got %v", testCert, cert)
	}

	_, err = ts.GetCertificate(ctx, "nonExistentCert")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGetCertChain(t *testing.T) {
	ts := NewTrustStore()
	ctx := context.Background()

	// Generate a test certificate chain
	testCertChain := []*x509.Certificate{
		{
			SerialNumber: big.NewInt(12345),
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(24 * time.Hour),
		},
		{
			SerialNumber: big.NewInt(67890),
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(24 * time.Hour),
		},
	}
	ts.(*truststore).certChains["testCertChain"] = testCertChain

	chain, err := ts.GetCertChain(ctx, "testCertChain")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(chain) != len(testCertChain) {
		t.Fatalf("expected chain length %d, got %d", len(testCertChain), len(chain))
	}
	for i, cert := range chain {
		if cert != testCertChain[i] {
			t.Fatalf("expected certificate %v, got %v", testCertChain[i], cert)
		}
	}

	_, err = ts.GetCertChain(ctx, "nonExistentCertChain")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
