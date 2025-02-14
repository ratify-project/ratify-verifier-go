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
	"crypto"
	"encoding/json"
	"fmt"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/ratify-project/ratify-go"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	"github.com/sigstore/sigstore/pkg/signature"
	"oras.land/oras-go/v2/registry"
)

const (
	cosignVerifierType = "cosign"
	artifactTypeCosign = "application/vnd.dev.cosign.artifact.sig.v1+json"
)

// VerifierOptions contains the options for creating a new cosign verifier.
type VerifierOptions struct {
	// Name is the instance name of the verifier to be created. Required.
	Name string

	// KeysMap is a map of subject references to their corresponding public keys. Optional.
	KeysMap map[string]crypto.PublicKey

	// CheckOpts is the options for cosign signature verification. Optional.
	*cosign.CheckOpts
}

// Verifier is a ratify.Verifier implementation that verifies cosign
// signatures.
type Verifier struct {
	name    string
	keysMap map[string]crypto.PublicKey
	*cosign.CheckOpts
}

// NewVerifier creates a new cosign verifier.
//
// Parameters:
// - opts: Options for creating the verifier, including the name and check options.
func NewVerifier(opts *VerifierOptions) (*Verifier, error) {
	return &Verifier{
		// Set the name of the verifier from the provided options.
		name: opts.Name,
		// Set the keys map from the provided options.
		keysMap: opts.KeysMap,
		// Set the cosign check options from the provided options.
		CheckOpts: opts.CheckOpts,
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

// Verifiable returns true if the artifact is a cosign signature.
func (v *Verifier) Verifiable(artifact ocispec.Descriptor) bool {
	return artifact.ArtifactType == artifactTypeCosign &&
		artifact.MediaType == ocispec.MediaTypeImageManifest
}

// Verify verifies the cosign signature.
func (v *Verifier) Verify(ctx context.Context, opts *ratify.VerifyOptions) (*ratify.VerificationResult, error) {
	subjectRef, err := registry.ParseReference(opts.Subject)
	if err != nil {
		return nil, fmt.Errorf("failed to parse subject reference: %w", err)
	}
	// Use the Fulcio root certificate for keyless verification
	err = updateCheckOpts(opts.Subject, v.CheckOpts, v.keysMap, &DefaultCertOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to update signature verifier keys: %w", err)
	}

	signatureLayers, err := getSignatureBlobDesc(ctx, opts.Store, subjectRef, opts.SubjectDescriptor)
	if err != nil {
		return nil, fmt.Errorf("failed to get signature blob descriptor: %w", err)
	}
	result := &ratify.VerificationResult{
		Verifier: v,
	}

	for _, signatureDesc := range signatureLayers {
		staticOpts, err := staticLayerOpts(signatureDesc)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Cosign signature  %w", err)
		}
		signatureBlob, err := opts.Store.FetchBlobContent(ctx, subjectRef.Repository, signatureDesc)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch signature blob: %w", err)
		}
		sig, err := static.NewSignature(signatureBlob, signatureDesc.Annotations[static.SignatureAnnotationKey], staticOpts...)
		if err != nil {
			return nil, fmt.Errorf("failed to validate the cosign signature: %w", err)
		}

		// Omit SimpleClaimVerifier which verifies that sig.Payload() is a SimpleContainerImage payload.
		// This is omitted because the payload verification is not required for our use case,
		// and we only need to verify the signature itself.
		// This payload references the given image digest and contains the given annotations.
		_, err = cosign.VerifyBlobSignature(ctx, sig, v.CheckOpts)
		if err != nil {
			result.Err = err
			return result, nil
		}
	}
	result.Description = "cosign signature verification succeeded"
	return result, nil
}

func getSignatureBlobDesc(ctx context.Context, store ratify.Store, artifactRef registry.Reference, artifactDesc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	manifest, err := store.FetchImageManifest(ctx, artifactRef.Registry+"/"+artifactRef.Repository, artifactDesc)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch image manifest for artifact: %w", err)
	}

	var signatureLayers []ocispec.Descriptor
	for _, layer := range manifest.Layers {
		if layer.MediaType == artifactTypeCosign {
			signatureLayers = append(signatureLayers, layer)
		}
	}
	return signatureLayers, nil
}

// updateCheckOpts updates the signature verifierOpts by verifyOpts.
func updateCheckOpts(repo string, opts *cosign.CheckOpts, keysMap map[string]crypto.PublicKey, certOpt CertOptions) error {
	if opts.RekorClient == nil {
		opts.IgnoreTlog = true
	}

	hashType := crypto.SHA256
	key, exists := keysMap[repo]
	if !exists {
		// TODO: support passing certChain and no CARoots
		opts.SigVerifier = nil
		roots, err := certOpt.GetRoots()
		if err != nil || roots == nil {
			return err
		}
		opts.RootCerts = roots
		opts.IgnoreSCT = true

		opts.IntermediateCerts, err = certOpt.GetIntermediates()
		if err != nil {
			return err
		}
		return nil
	}
	verifier, err := signature.LoadVerifier(key, hashType)
	if err != nil {
		return err
	}
	opts.SigVerifier = verifier
	return nil
}

// staticLayerOpts builds the cosign options for static layer signatures.
//
// Parameters:
// - desc: The OCI descriptor of the signature layer.
//
// Returns:
// - A slice of static.Option containing the options for the static layer signature.
// - An error if there is an issue with unmarshalling the bundle or other processing.
func staticLayerOpts(desc ocispec.Descriptor) ([]static.Option, error) {
	options := []static.Option{
		static.WithAnnotations(desc.Annotations),
	}
	if cert, chain := desc.Annotations[static.CertificateAnnotationKey], desc.Annotations[static.ChainAnnotationKey]; cert != "" && chain != "" {
		options = append(options, static.WithCertChain([]byte(cert), []byte(chain)))
	}
	var rekorBundle bundle.RekorBundle = bundle.RekorBundle{}
	if val, ok := desc.Annotations[static.BundleAnnotationKey]; ok {
		if err := json.Unmarshal([]byte(val), &rekorBundle); err != nil {
			return nil, fmt.Errorf("failed to unmarshal rekor bundle: %w", err)
		}
		options = append(options, static.WithBundle(&rekorBundle))
	}

	return options, nil
}
