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
	HashAlgorithm int
	KeyRef        string
	Sk            bool
	Slot          string
	CertRef       string
	CertChain     string
	SCTRef        string
}

type TrustStoreImp struct {
	OptsMap    map[string]*VOptions
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

func (t *TrustStoreImp) GetVerifyOpts(subjectRef string) (*VOptions, error) {
	return t.OptsMap[subjectRef], nil
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
