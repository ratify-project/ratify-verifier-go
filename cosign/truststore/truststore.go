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
	"crypto"
	"crypto/x509"
	"fmt"
)

// TrustStore defines an interface for a trust store that provides methods
// to retrieve public keys, certificates, and certificate chains.
// Implementations of this interface are expected to provide the necessary logic
// to fetch and manage these cryptographic elements.
type TrustStore interface {
	// GetKey retrieves the public key for a given key reference.
	// keyRef: A string representing the key reference.
	// Returns a crypto.PublicKey and an error if the operation fails.
	GetKey(ctx context.Context, keyRef string) (crypto.PublicKey, error)

	// GetCertificate retrieves the certificate for a given certificate reference.
	// certRef: A string representing the certificate reference.
	// Returns a pointer to an x509.Certificate and an error if the operation fails.
	GetCertificate(ctx context.Context, certRef string) (*x509.Certificate, error)

	// GetCertChain retrieves the certificate chain for a given certificate chain reference.
	// certChain: A string representing the certificate chain reference.
	// Returns a slice of pointers to x509.Certificate and an error if the operation fails.
	GetCertChain(ctx context.Context, certChain string) ([]*x509.Certificate, error)
}

type truststore struct {
	keys         map[string]crypto.PublicKey
	certificates map[string]*x509.Certificate
	certChains   map[string][]*x509.Certificate
}

func NewTrustStore() TrustStore {
	return &truststore{
		keys:         make(map[string]crypto.PublicKey),
		certificates: make(map[string]*x509.Certificate),
		certChains:   make(map[string][]*x509.Certificate),
	}
}

// TODO: Add a NewTrustStoreWithOptions function to initialize the truststore with given options.
// The options should include initial keys, certificates, and certificate chains.
// The function signature should be:
// func NewTrustStoreWithOptions(keys map[string]crypto.PublicKey, certificates map[string]*x509.Certificate, certChains map[string][]*x509.Certificate) TrustStore

func (t *truststore) GetKey(ctx context.Context, keyRef string) (crypto.PublicKey, error) {
	key, exists := t.keys[keyRef]
	if !exists {
		return nil, fmt.Errorf("key not found: %s", keyRef)
	}
	return key, nil

}

func (t *truststore) GetCertificate(ctx context.Context, certRef string) (*x509.Certificate, error) {
	cert, exists := t.certificates[certRef]
	if !exists {
		return nil, fmt.Errorf("certificate not found for reference: %s", certRef)
	}
	return cert, nil

}

func (t *truststore) GetCertChain(ctx context.Context, certChain string) ([]*x509.Certificate, error) {
	chain, exists := t.certChains[certChain]
	if !exists {
		return nil, fmt.Errorf("certificate chain not found: %s", certChain)
	}
	return chain, nil
}
