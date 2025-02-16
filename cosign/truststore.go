package cosign

import (
	"crypto"
	"crypto/x509"
)

type TrustStore interface {
	GetKey(keyRef string) (crypto.PublicKey, error)
	GetCert(certRef string) (*x509.Certificate, error)
	GetCertChain(certChain string) ([]*x509.Certificate, error)
}

type TrustStoreImp struct {
	keysMap    map[string]crypto.PublicKey
	certMap    map[string]*x509.Certificate
	certChains map[string][]*x509.Certificate
}

func NewWithOpts(opts *VerifierOptions) TrustStore {
	return &TrustStoreImp{
		keysMap:    make(map[string]crypto.PublicKey),
		certMap:    make(map[string]*x509.Certificate),
		certChains: make(map[string][]*x509.Certificate),
	}
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
