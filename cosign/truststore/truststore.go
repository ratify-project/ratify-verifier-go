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
	"crypto"
	"crypto/x509"
)

// TrustStore defines an interface for a trust store that provides methods
// to retrieve verification options, public keys, certificates, and certificate chains.
// Implementations of this interface are expected to provide the necessary logic
// to fetch and manage these cryptographic elements.
type TrustStore interface {
	// GetKey retrieves the public key for a given key reference.
	// keyRef: A string representing the key reference.
	// Returns a crypto.PublicKey and an error if the operation fails.
	GetKey(keyRef string) (crypto.PublicKey, error)

	// GetCert retrieves the certificate for a given certificate reference.
	// certRef: A string representing the certificate reference.
	// Returns a pointer to an x509.Certificate and an error if the operation fails.
	GetCert(certRef string) (*x509.Certificate, error)

	// GetCertChain retrieves the certificate chain for a given certificate chain reference.
	// certChain: A string representing the certificate chain reference.
	// Returns a slice of pointers to x509.Certificate and an error if the operation fails.
	GetCertChain(certChain string) ([]*x509.Certificate, error)
}

type truststore struct {
	keysMap    map[string]crypto.PublicKey
	certMap    map[string]*x509.Certificate
	certChains map[string][]*x509.Certificate
}

func New() TrustStore {
	return &truststore{
		keysMap:    make(map[string]crypto.PublicKey),
		certMap:    make(map[string]*x509.Certificate),
		certChains: make(map[string][]*x509.Certificate),
	}
}

// TODO: add a new with options to init the map with given options

func (t *truststore) GetKey(keyRef string) (crypto.PublicKey, error) {
	return t.keysMap[keyRef], nil
}

func (t *truststore) GetCert(certRef string) (*x509.Certificate, error) {
	return t.certMap[certRef], nil
}

func (t *truststore) GetCertChain(certChain string) ([]*x509.Certificate, error) {
	return t.certChains[certChain], nil
}
