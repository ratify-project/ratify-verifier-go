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

package verifycontextoptions

import (
	"crypto"
	"fmt"
)

// VerifyContext holds the options for verifying a context.
type VerifyContext struct {
	// CheckClaims indicates whether to check claims.
	CheckClaims bool
	// RekorURL is the URL of the Rekor transparency log.
	RekorURL string
	// IgnoreTlog indicates whether to ignore the transparency log.
	IgnoreTlog bool

	// HashAlgorithm is the hash algorithm to use.
	HashAlgorithm crypto.Hash
	// KeyRef is the reference to the key.
	KeyRef string
	// Sk indicates whether to use a security key.
	Sk bool
	// Slot is the slot to use for the security key.
	Slot string
	// SignatureRef is the reference to the signature.
	SignatureRef string

	// CertRef is the reference to the certificate.
	CertRef string
	// CAIntermediates is the path to the CA intermediates.
	CAIntermediates string
	// CARoots is the path to the CA roots.
	CARoots string
	// CertChain is the certificate chain.
	CertChain string

	// IgnoreSCT indicates whether to ignore the Signed Certificate Timestamp.
	IgnoreSCT bool
	// SCTRef is the reference to the Signed Certificate Timestamp.
	SCTRef string

	// UseSignedTimestamps indicates whether to use signed timestamps.
	UseSignedTimestamps bool
	// TSACertChainPath is the path to the TSA certificate chain.
	TSACertChainPath string

	// MaxWorkers is the maximum number of workers to use for parallel verification.
	// The default value is 10.
	MaxWorkers int
}

// VerifyContextOptions defines an interface for retrieving verification options
// for a given subject reference.
type VerifyContextOptions interface {
	// GetVerifyOpts retrieves the verification options for a given subject reference.
	GetVerifyOpts(subjectRef string) (*VerifyContext, error)
}

type verifyContextOptions struct {
	optsMap map[string]*VerifyContext
}

func New() VerifyContextOptions {
	return &verifyContextOptions{
		optsMap: make(map[string]*VerifyContext),
	}
}

// TODO: add a new with options to init the map with given options

func (v *verifyContextOptions) GetVerifyOpts(subjectRef string) (*VerifyContext, error) {
	opts, ok := v.optsMap[subjectRef]
	if !ok {
		return nil, fmt.Errorf("failed to get verify options")
	}
	return opts, nil
}
