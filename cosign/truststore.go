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

package cosign

import (
	"crypto"
	"crypto/x509"
)

type TrustStore interface {
	GetVerifyOpts(subjectRef string) (*VOptions, error)
	GetKey(keyRef string) (crypto.PublicKey, error)
	GetCert(certRef string) (*x509.Certificate, error)
	GetCertChain(certChain string) ([]*x509.Certificate, error)
}

type VOptions struct {
	HashAlgorithm crypto.Hash
	KeyRef        string
	Sk            bool
	Slot          string
	CertRef       string
	CertChain     string
	SCTRef        string
	IgnoreSCT     bool
}

type TrustStoreImp struct {
	optsMap    map[string]*VOptions
	keysMap    map[string]crypto.PublicKey
	certMap    map[string]*x509.Certificate
	certChains map[string][]*x509.Certificate
}

func NewWithOpts(opts *VerifierOptions) TrustStore {
	// TODO: get maps from opts.VerifyCommand
	return &TrustStoreImp{
		optsMap:    make(map[string]*VOptions),
		keysMap:    make(map[string]crypto.PublicKey),
		certMap:    make(map[string]*x509.Certificate),
		certChains: make(map[string][]*x509.Certificate),
	}
}

func (t *TrustStoreImp) GetVerifyOpts(subjectRef string) (*VOptions, error) {
	return t.optsMap[subjectRef], nil
}

func (t *TrustStoreImp) GetKey(keyRef string) (crypto.PublicKey, error) {
	return t.keysMap[keyRef], nil
}

func (t *TrustStoreImp) GetCert(certRef string) (*x509.Certificate, error) {
	return t.certMap[certRef], nil
}

func (t *TrustStoreImp) GetCertChain(certChain string) ([]*x509.Certificate, error) {
	return t.certChains[certChain], nil
}
