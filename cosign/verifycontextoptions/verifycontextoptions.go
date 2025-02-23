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

	"github.com/sigstore/cosign/v2/pkg/cosign"
)

// VerifyContext holds the options for verifying a context.
type VerifyContext struct {
	// CheckClaims indicates whether to check claims.
	CheckClaims bool
	// RekorURL is the URL of the Rekor transparency log.
	RekorURL string

	// CommonVerifyOptions represents the common options used for verification
	// in the cosign verifier.
	CommonVerifyOptions CommonVerifyOptions
	// SecurityKeyOptions represents the options for configuring security keys
	// used in the verification process.
	SecurityKeyOptions SecurityKeyOptions
	// CertVerifyOptions represents the options for configuring certificate
	// verification in the verification process.
	CertVerifyOptions CertVerifyOptions

	// IgnoreSCT indicates whether to ignore the Signed Certificate Timestamp.
	IgnoreSCT bool
	// SCTRef is the reference to the Signed Certificate Timestamp.
	SCTRef string
	// CTLogPubKeys, if set, is used to validate SCTs against those keys.
	// It is a map from log id to LogIDMetadata. It is a map from LogID to crypto.PublicKey. LogID is derived from the PublicKey (see RFC 6962 S3.2).
	CTLogPubKeys *cosign.TrustedTransparencyLogPubKeys
	// KeyRef is the reference to the key.
	KeyRef string
	// HashAlgorithm is the hash algorithm to use.
	HashAlgorithm crypto.Hash
}

type CommonVerifyOptions struct {
	Offline             bool // Force offline verification
	TSACertChainPath    string
	IgnoreTlog          bool
	MaxWorkers          int
	UseSignedTimestamps bool
}

// CertVerifyOptions is the wrapper for certificate verification.
type CertVerifyOptions struct {
	Cert                         string
	CertIdentity                 string
	CertIdentityRegexp           string
	CertOidcIssuer               string
	CertOidcIssuerRegexp         string
	CertGithubWorkflowTrigger    string
	CertGithubWorkflowSha        string
	CertGithubWorkflowName       string
	CertGithubWorkflowRepository string
	CertGithubWorkflowRef        string
	CAIntermediates              string
	CARoots                      string
	CertChain                    string
	SCT                          string
	IgnoreSCT                    bool
}

// SecurityKeyOptions is the wrapper for security key verification.
type SecurityKeyOptions struct {
	// Sk indicates whether to use a security key.
	Sk bool
	// Slot is the slot to use for the security key.
	Slot string
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

func NewVerifyContextOptions() VerifyContextOptions {
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
