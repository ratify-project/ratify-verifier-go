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

package notation

import (
	"context"
	"fmt"

	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/plugin"
	notationVerifier "github.com/notaryproject/notation-go/verifier"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/ratify-project/ratify-go"
	"oras.land/oras-go/v2/registry"
)

const (
	notationVerifierType          = "notation"
	notationSignatureArtifactType = "application/vnd.cncf.notary.signature"
	maxManifestSizeLimit          = 4 * 1024 * 1024  // 4 MiB
	maxBlobSizeLimit              = 32 * 1024 * 1024 // 32 MiB
)

// NewVerifierOptions contains the options for creating a new Notation verifier.
type NewVerifierOptions struct {
	// Name is the name of the verifier. Required.
	Name string

	// TrustPolicyDoc is a trustpolicy.json document. It should follow the spec:
	// https://github.com/notaryproject/notation-go/blob/release-1.3/verifier/trustpolicy/oci.go#L29
	// Required.
	TrustPolicyDoc *trustpolicy.Document

	// TrustStore manages the certificates in the trust store. It should
	// implement the truststore.X509TrustStore interface:
	// https://github.com/notaryproject/notation-go/blob/release-1.3/verifier/truststore/truststore.go#L52
	// Required.
	TrustStore truststore.X509TrustStore

	// PluginManager manages the plugins installed for Notation verifier. It
	// should implement the plugin.Manager interface:
	// https://github.com/notaryproject/notation-go/blob/release-1.3/plugin/manager.go#L33
	// Optional.
	PluginManager plugin.Manager
}

// Verifier is a ratify.Verifier implementation that verifies Notation
// signatures.
type Verifier struct {
	name        string
	sigVerifier notation.Verifier
}

// NewVerifier creates a new Notation verifier.
func NewVerifier(opts *NewVerifierOptions) (ratify.Verifier, error) {
	verifier, err := notationVerifier.New(opts.TrustPolicyDoc, opts.TrustStore, opts.PluginManager)
	if err != nil {
		return nil, fmt.Errorf("failed to create notation verifier: %w", err)
	}

	return &Verifier{
		name:        opts.Name,
		sigVerifier: verifier,
	}, nil
}

// Name returns the name of the verifier.
func (v *Verifier) Name() string {
	return v.name
}

// Type returns the type of the verifier which is always `notation`.
func (v *Verifier) Type() string {
	return notationVerifierType
}

// Verifiable returns true if the artifact is a Notation signature.
func (v *Verifier) Verifiable(artifact ocispec.Descriptor) bool {
	return artifact.ArtifactType == notationSignatureArtifactType && artifact.MediaType == ocispec.MediaTypeImageManifest
}

// Verify verifies the Notation signature.
func (v *Verifier) Verify(ctx context.Context, opts *ratify.VerifyOptions) (*ratify.VerificationResult, error) {
	subjectRef, err := registry.ParseReference(opts.Subject)
	if err != nil {
		return nil, fmt.Errorf("failed to parse subject reference: %w", err)
	}

	signatureDesc, err := v.getSignatureBlobDesc(ctx, opts.Store, subjectRef, opts.SubjectDescriptor)
	if err != nil {
		return nil, fmt.Errorf("failed to get signature blob descriptor: %w", err)
	}

	signatureBlob, err := opts.Store.FetchBlobContent(ctx, subjectRef.Repository, signatureDesc)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch signature blob: %w", err)
	}

	result := &ratify.VerificationResult{
		Verifier: v,
	}
	if outcome, err := v.verifySignature(ctx, opts.Subject, opts.SubjectDescriptor, signatureBlob, signatureDesc.MediaType); err != nil {
		result.Err = err
	} else {
		cert := outcome.EnvelopeContent.SignerInfo.CertificateChain[0]
		result.Detail = map[string]string{
			"Issuer": cert.Issuer.String(),
			"SN":     cert.Subject.String(),
		}
		result.Description = "Notation signature verification succeeded"
	}

	return result, nil
}

func (v *Verifier) getSignatureBlobDesc(ctx context.Context, store ratify.Store, artifactRef registry.Reference, artifactDesc ocispec.Descriptor) (ocispec.Descriptor, error) {
	if artifactDesc.Size > maxManifestSizeLimit {
		return ocispec.Descriptor{}, fmt.Errorf("signature manifest too large: %d bytes", artifactDesc.Size)
	}

	manifest, err := store.FetchImageManifest(ctx, artifactRef.Registry+"/"+artifactRef.Repository, artifactDesc)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("failed to fetch image manifest for artifact: %w", err)
	}

	if len(manifest.Layers) != 1 {
		return ocispec.Descriptor{}, fmt.Errorf("notation signature manifest requries exactly one signature envelope blob, got %d", len(manifest.Layers))
	}

	signatureDesc := manifest.Layers[0]
	if signatureDesc.Size > maxBlobSizeLimit {
		return ocispec.Descriptor{}, fmt.Errorf("signature blob too large: %d bytes", signatureDesc.Size)
	}

	return signatureDesc, nil
}

func (v *Verifier) verifySignature(ctx context.Context, subject string, subjectDesc ocispec.Descriptor, signature []byte, signatureMediaType string) (*notation.VerificationOutcome, error) {
	opts := notation.VerifierVerifyOptions{
		SignatureMediaType: signatureMediaType,
		ArtifactReference:  subject,
	}
	return v.sigVerifier.Verify(ctx, subjectDesc, signature, opts)
}
