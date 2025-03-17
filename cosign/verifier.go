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
	"context"
	"fmt"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	ratify "github.com/ratify-project/ratify-go"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const (
	cosignVerifierType = "cosign"
	artifactTypeCosign = "vnd.dev.cosign.artifact.sig.v1+json"
)

// VerifierOptions contains the options for creating a new Cosign verifier.
type VerifierOptions struct {
	Name                  string
	CosignVerifierOptions []verify.VerifierOption
	TrustedMaterial       root.TrustedMaterial
}

// Verifier is a ratify.Verifier implementation that verifies Cosign
// signatures.
type Verifier struct {
	name             string
	trustedPolicyMux map[string]trustedPolicyOption
	verifier         *verify.SignedEntityVerifier
}

// NewVerifier creates a new Cosign verifier.
func NewVerifier(opts *VerifierOptions) (*Verifier, error) {
	v, err := verify.NewSignedEntityVerifier(opts.TrustedMaterial, opts.CosignVerifierOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create cosign verifier: %w", err)
	}
	return &Verifier{
		name:     opts.Name,
		verifier: v,
	}, nil
}

// Name returns the name of the verifier.
func (v *Verifier) Name() string {
	return v.name
}

// Type returns the type of the verifier which is always `cosign`.
func (v *Verifier) Type() string {
	return cosignVerifierType
}

// Verifiable returns true if the artifact is a Cosign signature.
// Require signer sign with flag RegistryReferrersModeOCI11
func (v *Verifier) Verifiable(artifact ocispec.Descriptor) bool {
	return artifact.ArtifactType == artifactTypeCosign && artifact.MediaType == ocispec.MediaTypeImageManifest
}

// Verify verifies the Cosign signature.
func (v *Verifier) Verify(ctx context.Context, opts *ratify.VerifyOptions) (*ratify.VerificationResult, error) {
	result := &ratify.VerificationResult{
		Verifier: v,
	}
	b, _, err := bundleFromOCIImage(opts.Repository+"@"+opts.SubjectDescriptor.Digest.String(), requireTlog(), requireTimestamp())
	if err != nil {
		result.Err = err
		return result, nil
	}
	var artifactPolicy verify.ArtifactPolicyOption
	var identityPolicies []verify.PolicyOption
	// Verify checks the cryptographic integrity
	outcome, err := v.verifier.Verify(b, verify.NewPolicy(artifactPolicy, identityPolicies...))
	if err != nil {
		result.Err = err
		return result, nil
	}

	cert := outcome.Signature.Certificate
	result.Detail = map[string]any{
		"Issuer":  cert.CertificateIssuer,
		"SN":      cert.SubjectAlternativeName,
		"Details": outcome,
	}
	result.Description = "Cosign signature verification succeeded"
	return result, nil
}

// TODO: Implement the following functions
func requireTlog() bool {
	return true
}

// TODO: Implement the following functions
func requireTimestamp() bool {
	return true
}
