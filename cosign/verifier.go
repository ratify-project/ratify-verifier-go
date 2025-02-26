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
	artifactTypeCosign = "application/vnd.dev.cosign.artifact.sig.v1+json"
)

// VerifierOptions contains the options for creating a new Cosign verifier.
type VerifierOptions struct {
	// Name is the instance name of the verifier to be created. Required.
	Name string

	// TrustedMaterial is the trusted material used by the verifier.
	TrustedMaterial root.TrustedMaterial

	// Options is the additional options for the cosign verifier
	Options verify.VerifierOption
}

// Verifier is a ratify.Verifier implementation that verifies Cosign
// signatures.
type Verifier struct {
	name     string
	verifier verify.SignedEntityVerifier
}

// NewVerifier creates a new Cosign verifier.
func NewVerifier(opts *VerifierOptions) (*Verifier, error) {
	v, err := verify.NewSignedEntityVerifier(opts.TrustedMaterial, opts.Options)
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
func (v *Verifier) Verifiable(artifact ocispec.Descriptor) bool {
	return artifact.ArtifactType == artifactTypeCosign &&
		artifact.MediaType == ocispec.MediaTypeImageManifest
}

// Verify verifies the Cosign signature.
func (v *Verifier) Verify(ctx context.Context, opts *ratify.VerifyOptions) (*ratify.VerificationResult, error) {
	// 	signatureDesc, err := v.getSignatureBlobDesc(ctx, opts.Store, opts.Repository, opts.ArtifactDescriptor)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("failed to get signature blob descriptor: %w", err)
	// 	}

	// 	signatureBlob, err := opts.Store.FetchBlob(ctx, opts.Repository, signatureDesc)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("failed to fetch signature blob: %w", err)
	// 	}
	// }
	// 	verifyOpts := notation.VerifierVerifyOptions{
	// 		SignatureMediaType: signatureDesc.MediaType,
	// 		ArtifactReference:  opts.Repository + "@" + opts.SubjectDescriptor.Digest.String(),
	// 	}

	result := &ratify.VerificationResult{
		Verifier: v,
	}

	var entity verify.SignedEntity
	var pb verify.PolicyBuilder

	outcome, err := v.verifier.Verify(entity, pb)
	if err != nil {
		result.Err = err
		return result, nil
	}
	cert := outcome.CertIdentity
	result.Detail = map[string]string{
		"Issuer": cert.Issuer.String(),
		"SN":     cert.SubjectAlternativeName.SubjectAlternativeName.String(),
	}
	result.Description = "Cosign signature verification succeeded"
	return result, nil
}
