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
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const (
	cosignVerifierType = "cosign"
	artifactTypeCosign = "application/vnd.dev.cosign.artifact.sig.v1+json"
)

// VerifierOptions contains the options for creating a new Cosign verifier.
type VerifierOptions struct {
	Name                  string
	CosignVerifierOption  *cosignVerifierOption
	TrustedMaterialOption *trustedMaterialOption
	MinBundleVersion      string
	TrustedPublicOptions  []trustedPolicyOption
}

// Verifier is a ratify.Verifier implementation that verifies Cosign
// signatures.
type Verifier struct {
	name                 string
	minBundleVersion     string
	trustedPolicyOptions []trustedPolicyOption
	verifier             *verify.SignedEntityVerifier
}

// NewVerifier creates a new Cosign verifier.
func NewVerifier(opts *VerifierOptions) (*Verifier, error) {
	ctx := context.Background()
	options := prepareVerifierOptions(opts.CosignVerifierOption)
	trustmaterial, err := prepareTrustedMaterial(ctx, opts.TrustedMaterialOption)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare trusted material: %w", err)
	}
	v, err := verify.NewSignedEntityVerifier(trustmaterial, options...)
	if err != nil {
		return nil, fmt.Errorf("failed to create cosign verifier: %w", err)
	}

	return &Verifier{
		name:                 opts.Name,
		minBundleVersion:     opts.MinBundleVersion,
		trustedPolicyOptions: opts.TrustedPublicOptions,
		verifier:             v,
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
func (v *Verifier) Verifiable(artifact ocispec.Descriptor) bool {
	return true
}

// Verify verifies the Cosign signature.
func (v *Verifier) Verify(ctx context.Context, opts *ratify.VerifyOptions) (*ratify.VerificationResult, error) {
	// TODO: prepareVerifierOptions
	result := &ratify.VerificationResult{
		Verifier: v,
	}

	signedEntityDesc, err := getSignatureBlobDesc(ctx, opts.Store, opts.Repository, opts.ArtifactDescriptor)
	if err != nil {
		result.Err = err
		return result, nil
	}
	entity, err := prepareSignedEntity(signedEntityDesc, v.minBundleVersion)
	if err != nil {
		result.Err = err
		return result, nil
	}
	trustPolicyOption, err := resolveTrustPolicy(signedEntityDesc)
	if err != nil {
		result.Err = err
		return result, nil
	}
	pb, err := preparePolicyBuilder(ctx, trustPolicyOption)
	if err != nil {
		result.Err = err
		return result, nil
	}
	outcome, err := v.verifier.Verify(entity, pb)
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
