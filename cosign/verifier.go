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
	"crypto/x509"
	"encoding/json"
	"fmt"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/ratify-project/ratify-go"
	"github.com/ratify-project/ratify-verifier-go/cosign/truststore"
	"github.com/ratify-project/ratify-verifier-go/cosign/verifycontextoptions"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	rekor "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/sigstore/pkg/fulcioroots"
	"github.com/sigstore/sigstore/pkg/signature"
)

const (
	cosignVerifierType = "cosign"
	defaultRekorURL    = "https://rekor.sigstore.dev"
	artifactTypeCosign = "application/vnd.dev.cosign.artifact.sig.v1+json"
)

// VerifierOptions contains the options for creating a new cosign verifier.
type VerifierOptions struct {
	// Name is the instance name of the verifier to be created. Required.
	Name string

	// VerifyContextOptions represents the options for verifying the context.
	VerifyContextOptions verifycontextoptions.VerifyContextOptions

	// Truststore is the truststore that contains the keys and certificates used for verification.
	Truststore truststore.TrustStore
}

// Verifier is a ratify.Verifier implementation that verifies cosign
// signatures.
type Verifier struct {
	name                 string
	verifyContextOptions verifycontextoptions.VerifyContextOptions
	truststore           truststore.TrustStore
}

// NewVerifier creates a new cosign verifier.
func NewVerifier(opts *VerifierOptions) (*Verifier, error) {
	// TODO: Consider creating a cosign verifier that validates the default verify context
	// by ensuring that the VerifyContextOptions are properly initialized and that the
	// Truststore contains the necessary keys and certificates for verification.
	return &Verifier{
		name:                 opts.Name,
		verifyContextOptions: opts.VerifyContextOptions,
		truststore:           opts.Truststore,
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
	vctx, err := v.verifyContextOptions.GetVerifyOpts(opts.Repository + "@" + opts.SubjectDescriptor.Digest.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get verify context from options: %w", err)
	}
	checkOpts, err := getCheckOpts(ctx, vctx, v.truststore)
	if err != nil {
		return nil, fmt.Errorf("failed to create cosign check options: %w", err)
	}

	sig, signatureDescHash, err := getSignatureAndHash(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get signature and signature descriptor: %w", err)
	}

	result := &ratify.VerificationResult{
		Verifier: v,
	}

	bundleVerified, err := cosign.VerifyImageSignature(ctx, sig, signatureDescHash, checkOpts)
	if err != nil {
		result.Err = err
		return result, nil
	}
	if !bundleVerified {
		result.Description = "no valid cosign signatures found"
		return result, nil
	}
	result.Description = "cosign signature verification succeeded"
	return result, nil
}

func getCheckOpts(ctx context.Context, vctx *verifycontextoptions.VerifyContext, s truststore.TrustStore) (opts *cosign.CheckOpts, err error) {
	opts = &cosign.CheckOpts{}

	if vctx.CheckClaims {
		opts.ClaimVerifier = cosign.SimpleClaimVerifier
	}

	if err := setRekorOptions(ctx, vctx, opts); err != nil {
		return nil, err
	}

	if err := setTSAOptions(ctx, vctx, opts); err != nil {
		return nil, err
	}

	if vctx.KeyRef == "" && !vctx.CertVerifyOptions.IgnoreSCT {
		opts.CTLogPubKeys = vctx.CTLogPubKeys
	}

	sigVerifier, err := getSigVerifier(ctx, vctx, s, opts)
	if err != nil {
		return nil, err
	}
	opts.SigVerifier = sigVerifier
	opts.MaxWorkers = vctx.CommonVerifyOptions.MaxWorkers

	return opts, nil
}

func setRekorOptions(ctx context.Context, vctx *verifycontextoptions.VerifyContext, opts *cosign.CheckOpts) error {
	if !vctx.CommonVerifyOptions.IgnoreTlog {
		rekorURL := defaultRekorURL
		if vctx.RekorURL != "" {
			rekorURL = vctx.RekorURL
		}

		rekorClient, err := rekor.GetRekorClient(rekorURL)
		if err != nil {
			return err
		}
		opts.RekorClient = rekorClient

		opts.RekorPubKeys, err = cosign.GetRekorPubs(ctx)
		if err != nil {
			return err
		}
	}
	return nil
}

func setTSAOptions(ctx context.Context, vctx *verifycontextoptions.VerifyContext, opts *cosign.CheckOpts) error {
	if vctx.CommonVerifyOptions.TSACertChainPath != "" || vctx.CommonVerifyOptions.UseSignedTimestamps {
		tsaCertificates, err := cosign.GetTSACerts(ctx, vctx.CommonVerifyOptions.TSACertChainPath, cosign.GetTufTargets)
		if err != nil {
			return err
		}
		opts.TSACertificate = tsaCertificates.LeafCert
		opts.TSARootCertificates = tsaCertificates.RootCert
		opts.TSAIntermediateCertificates = tsaCertificates.IntermediateCerts
	}
	return nil
}

// getSigVerifier retrieves a signature verifier based on the provided context and verification options.
// It supports verification using a key reference or a certificate.
func getSigVerifier(ctx context.Context, vctx *verifycontextoptions.VerifyContext, s truststore.TrustStore, opts *cosign.CheckOpts) (signature.Verifier, error) {
	var sigVerifier signature.Verifier
	switch {
	case vctx.KeyRef != "":
		key, err := s.GetKey(ctx, vctx.KeyRef)
		if err != nil {
			return nil, err
		}
		hashAlgorithm := crypto.SHA256
		if vctx.HashAlgorithm != 0 {
			hashAlgorithm = vctx.HashAlgorithm
		}
		sigVerifier, err = signature.LoadVerifier(key, hashAlgorithm)
		if err != nil {
			return nil, err
		}
	case vctx.CertVerifyOptions.Cert != "":
		cert, err := s.GetCertificate(ctx, vctx.CertVerifyOptions.Cert)
		if err != nil {
			return nil, err
		}
		sigVerifier, err = getKeylessVerifier(ctx, cert, vctx, s, opts)
		if err != nil {
			return nil, err
		}
	default:
		// Do nothing. Neither keyRef, Sk, nor certRef were set - can happen for example when using Fulcio and TSA.
	}
	return sigVerifier, nil
}

// getKeylessVerifier returns a keyless verifier based on the provided certificate and verification context options.
// It uses the provided trust store and cosign check options to validate and unpack the certificate.
// Additionally, it sets the Signed Certificate Timestamp (SCT) options if provided in the verification context options.
func getKeylessVerifier(ctx context.Context, cert *x509.Certificate, vctx *verifycontextoptions.VerifyContext, s truststore.TrustStore, opts *cosign.CheckOpts) (signature.Verifier, error) {
	var keylessVerifier signature.Verifier
	var err error
	switch {
	case vctx.CertVerifyOptions.CertChain == "" && opts.RootCerts == nil:
		opts.RootCerts, err = fulcioroots.Get()
		if err != nil {
			return nil, err
		}
		opts.IntermediateCerts, err = fulcioroots.GetIntermediates()
		if err != nil {
			return nil, err
		}
		keylessVerifier, err = cosign.ValidateAndUnpackCert(cert, opts)
		if err != nil {
			return nil, err
		}
	case vctx.CertVerifyOptions.CertChain != "":
		chain, err := s.GetCertChain(ctx, vctx.CertVerifyOptions.CertChain)
		if err != nil {
			return nil, err
		}
		keylessVerifier, err = cosign.ValidateAndUnpackCertWithChain(cert, chain, opts)
		if err != nil {
			return nil, err
		}
	case vctx.CertVerifyOptions.CARoots != nil:
		opts.RootCerts = vctx.CertVerifyOptions.CARoots
		keylessVerifier, err = cosign.ValidateAndUnpackCert(cert, opts)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("invalid certificate options")
	}

	if vctx.CertVerifyOptions.SCT != nil {
		opts.IgnoreSCT = vctx.CertVerifyOptions.IgnoreSCT
		opts.SCT = vctx.CertVerifyOptions.SCT
	}
	return keylessVerifier, nil
}

// getSignatureAndHash retrieves the latest OCI signature and its corresponding hash for a given artifact.
func getSignatureAndHash(ctx context.Context, opts *ratify.VerifyOptions) (oci.Signature, v1.Hash, error) {
	signatureDescriptors, err := getSignatureBlobDesc(ctx, opts.Store, opts.Repository, opts.ArtifactDescriptor)
	if err != nil {
		return nil, v1.Hash{}, fmt.Errorf("failed to get signature blob descriptor: %w", err)
	}

	// TODO: check with cosign library for the signature verification update
	// For now this verifier will only verify the latest signature instead of one of all signatures
	//
	// Reference: https://github.com/sigstore/cosign/blob/main/pkg/cosign/verify.go#L722
	// Reference: https://github.com/sigstore/cosign/blob/main/pkg/cosign/verify.go#L1478
	numResults := len(signatureDescriptors)
	if numResults == 0 {
		return nil, v1.Hash{}, fmt.Errorf("unable to locate reference with artifactType %s", artifactTypeCosign)
	}

	signatureDesc := signatureDescriptors[numResults-1]

	staticOpts, err := getStaticLayerOpts(signatureDesc)
	if err != nil {
		return nil, v1.Hash{}, fmt.Errorf("failed to parse Cosign signature  %w", err)
	}
	signatureBlob, err := opts.Store.FetchBlob(ctx, opts.Repository, signatureDesc)
	if err != nil {
		return nil, v1.Hash{}, fmt.Errorf("failed to fetch signature blob: %w", err)
	}
	sig, err := static.NewSignature(signatureBlob, signatureDesc.Annotations[static.SignatureAnnotationKey], staticOpts...)
	if err != nil {
		return nil, v1.Hash{}, fmt.Errorf("failed to validate the cosign signature: %w", err)
	}

	// create the hash of the subject image descriptor (used as the hashed payload)
	signatureDescHash := v1.Hash{
		Algorithm: signatureDesc.Digest.Algorithm().String(),
		Hex:       signatureDesc.Digest.Hex(),
	}
	return sig, signatureDescHash, nil
}

// getStaticLayerOpts generates a list of static options based on the provided OCI descriptor.
// It extracts annotations, certificate chains, and Rekor bundles from the descriptor's annotations
// and constructs corresponding static options.
func getStaticLayerOpts(desc ocispec.Descriptor) ([]static.Option, error) {
	options := []static.Option{}

	options = append(options, static.WithAnnotations(desc.Annotations))
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

// getSignatureBlobDesc retrieves the signature blob descriptors for a given artifact from the specified store.
// It fetches the manifest for the artifact, unmarshals it, and extracts the layers that match the Cosign signature media type.
func getSignatureBlobDesc(ctx context.Context, store ratify.Store, repo string, artifactDesc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	manifestBytes, err := store.FetchManifest(ctx, repo, artifactDesc)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch manifest for artifact: %w", err)
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("failed to unmarshal manifest: %w", err)
	}

	var signatureDescriptors []ocispec.Descriptor
	for _, layer := range manifest.Layers {
		if layer.MediaType == artifactTypeCosign {
			signatureDescriptors = append(signatureDescriptors, layer)
		}
	}
	return signatureDescriptors, nil
}
