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
	"crypto/x509"
	"fmt"

	"github.com/sigstore/cosign/v2/pkg/cosign"
)

// VerifyContextOptions defines an interface for retrieving verification options
// for a given subject reference.
type VerifyContextOptions interface {
	// GetVerifyOpts retrieves the verification options for a given subject reference.
	GetVerifyOpts(subjectRef string) (*VerifyContext, error)
}

// CommonVerifyOptions contains options for verifying signatures.
type CommonVerifyOptions struct {
	// Force offline verification
	Offline bool
	// Path to TSA certificate chain
	TSACertChainPath string
	// Ignore transparency log
	IgnoreTlog bool
	// Maximum number of workers
	MaxWorkers int
	// Use signed timestamps
	UseSignedTimestamps bool
}

// CertVerifyOptions is the wrapper for certificate verification.
type CertVerifyOptions struct {
	// Certificate
	Cert string
	// Certificate Identity
	CertIdentity string
	// Certificate Identity Regular Expression
	CertIdentityRegexp string
	// Certificate OIDC Issuer
	CertOidcIssuer string
	// Certificate OIDC Issuer Regular Expression
	CertOidcIssuerRegexp string
	// GitHub Workflow Trigger
	CertGithubWorkflowTrigger string
	// GitHub Workflow SHA
	CertGithubWorkflowSha string
	// GitHub Workflow Name
	CertGithubWorkflowName string
	// GitHub Workflow Repository
	CertGithubWorkflowRepository string
	// GitHub Workflow Reference
	CertGithubWorkflowRef string
	// CA Intermediates
	CAIntermediates string
	// CA Roots
	CARoots *x509.CertPool
	// Certificate Chain
	CertChain string
	// Signed Certificate Timestamp
	SCT []byte
	// Ignore Signed Certificate Timestamp
	IgnoreSCT bool
}

// VerifyContext holds the options for verifying a context.
type VerifyContext struct {
	// CheckClaims indicates whether to check claims.
	CheckClaims bool
	// RekorURL is the URL of the Rekor transparency log.
	RekorURL string
	// CommonVerifyOptions represents the common options used for verification in the cosign verifier.
	CommonVerifyOptions CommonVerifyOptions
	// CertVerifyOptions represents the options for configuring certificate verification in the verification process.
	CertVerifyOptions CertVerifyOptions
	// CTLogPubKeys, if set, is used to validate Signed Certificate Timestamps (SCTs) against the provided public keys. It is a map from LogID to crypto.PublicKey, where LogID is derived from the PublicKey (see RFC 6962 S3.2).
	CTLogPubKeys *cosign.TrustedTransparencyLogPubKeys
	// KeyRef is the reference to the key.
	KeyRef string
	// HashAlgorithm is the hash algorithm to use.
	HashAlgorithm crypto.Hash
}

type verifyContextOptions struct {
	optsMap map[string]*VerifyContext
}

func NewVerifyContextOptions() VerifyContextOptions {
	return &verifyContextOptions{
		optsMap: make(map[string]*VerifyContext),
	}
}

// TODO: NewVerifyContextOptionsWithMap initializes the verifyContextOptions with options.

func (v *verifyContextOptions) GetVerifyOpts(subjectRef string) (*VerifyContext, error) {
	opts, ok := v.optsMap[subjectRef]
	if !ok {
		return nil, fmt.Errorf("failed to get verify options")
	}
	return opts, nil
}
