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
	"errors"
	"fmt"
	"os"
	"path/filepath"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/ratify-project/ratify-go"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	verify "github.com/sigstore/cosign/v2/cmd/cosign/cli/verify"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v2/pkg/cosign/pivkey"
	"github.com/sigstore/cosign/v2/pkg/cosign/pkcs11key"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	"github.com/sigstore/sigstore/pkg/signature"
	"oras.land/oras-go/v2/registry"
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

	// VerifyCommand is a stuct contains params that executes the verification process.
	verify.VerifyCommand
}

// Verifier is a ratify.Verifier implementation that verifies cosign
// signatures.
type Verifier struct {
	name       string
	truststore TrustStore
	*cosign.CheckOpts
}

// NewVerifier creates a new cosign verifier.
//
// Parameters:
// - opts: Options for creating the verifier, including the name and check options.
func NewVerifier(opts *VerifierOptions) (*Verifier, error) {
	checkOpts, err := NewCheckOpts(context.Background(), &opts.VerifyCommand)
	if err != nil {
		return nil, fmt.Errorf("failed to update signature verifier keys: %w", err)
	}

	return &Verifier{
		// Set the name of the verifier from the provided options.
		name: opts.Name,
		// Set the keys map from the provided options.
		truststore: NewWithOpts(opts),
		// Set the cosign check options from the provided options.
		CheckOpts: checkOpts,
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
	v.MapSigVerifier(ctx, opts)

	subjectRef, err := registry.ParseReference(opts.Subject)
	if err != nil {
		return nil, fmt.Errorf("failed to parse subject reference: %w", err)
	}

	signatureLayers, err := getSignatureBlobDesc(ctx, opts.Store, subjectRef, opts.SubjectDescriptor)
	if err != nil {
		return nil, fmt.Errorf("failed to get signature blob descriptor: %w", err)
	}

	numResults := len(signatureLayers)
	if numResults == 0 {
		return nil, fmt.Errorf("unable to locate reference with artifactType %s", artifactTypeCosign)
	}

	signatureDesc := signatureLayers[numResults-1]

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

	// create the hash of the subject image descriptor (used as the hashed payload)
	signatureDescHash := v1.Hash{
		Algorithm: signatureDesc.Digest.Algorithm().String(),
		Hex:       signatureDesc.Digest.Hex(),
	}
	result := &ratify.VerificationResult{
		Verifier: v,
	}
	_, err = cosign.VerifyImageSignature(ctx, sig, signatureDescHash, v.CheckOpts)
	if err != nil {
		result.Err = err
		return result, nil
	}

	result.Description = "cosign signature verification succeeded"
	return result, nil
}

// MapSigVerifier maps and returns a signature verifier based on the provided VerifyCommand and CheckOpts.
// It supports different types of verifiers including key references, security keys, and certificate references.
func (v *Verifier) MapSigVerifier(ctx context.Context, opts *ratify.VerifyOptions) (err error) {
	c, err := getVerifyCommandFromOpts(v, opts)
	if err != nil {
		return fmt.Errorf("failed to get verify command from options: %w", err)
	}
	// Ignore Signed Certificate Timestamp if the flag is set or a key is provided
	if c.KeyRef == "" && !c.Sk && !c.IgnoreSCT {
		v.CheckOpts.CTLogPubKeys, err = cosign.GetCTLogPubs(ctx)
		if err != nil {
			return fmt.Errorf("getting ctlog public keys: %w", err)
		}
	}

	var pubKey signature.Verifier
	switch {
	case c.KeyRef != "":
		if c.HashAlgorithm == 0 {
			c.HashAlgorithm = crypto.SHA256
		}
		key, err := v.truststore.GetKey(c.KeyRef)
		if err != nil {
			return fmt.Errorf("getting key: %w", err)
		}
		pubKey, err = signature.LoadVerifier(key, c.HashAlgorithm)
		if err != nil {
			return err
		}
		pkcs11Key, ok := pubKey.(*pkcs11key.Key)
		if ok {
			defer pkcs11Key.Close()
		}
	case c.Sk:
		sk, err := pivkey.GetKeyWithSlot(c.Slot)
		defer sk.Close()
		if err != nil {
			return fmt.Errorf("opening piv token: %w", err)
		}
		pubKey, err = sk.Verifier()
		if err != nil {
			return fmt.Errorf("initializing piv token verifier: %w", err)
		}
	case c.CertRef != "":
		cert, err := v.truststore.GetCert(c.CertRef)
		if err != nil {
			return fmt.Errorf("getting certificate: %w", err)
		}
		switch {
		case c.CertChain == "" && v.CheckOpts.RootCerts == nil:
			// If no certChain and no CARoots are passed, the Fulcio root certificate will be used
			v.CheckOpts.RootCerts, err = fulcio.GetRoots()
			if err != nil {
				return fmt.Errorf("getting Fulcio roots: %w", err)
			}
			v.CheckOpts.IntermediateCerts, err = fulcio.GetIntermediates()
			if err != nil {
				return fmt.Errorf("getting Fulcio intermediates: %w", err)
			}
			pubKey, err = cosign.ValidateAndUnpackCert(cert, v.CheckOpts)
			if err != nil {
				return err
			}
		case c.CertChain != "":
			// Verify certificate with chain
			chain, err := v.truststore.GetCertChain(c.CertChain)
			if err != nil {
				return fmt.Errorf("getting certificate chain: %w", err)
			}
			pubKey, err = cosign.ValidateAndUnpackCertWithChain(cert, chain, v.CheckOpts)
			if err != nil {
				return err
			}
		case v.CheckOpts.RootCerts != nil:
			// Verify certificate with root (and if given, intermediate) certificate
			pubKey, err = cosign.ValidateAndUnpackCert(cert, v.CheckOpts)
			if err != nil {
				return err
			}
		default:
			return errors.New("no certificate chain provided to verify certificate")
		}

		if c.SCTRef != "" {
			sct, err := os.ReadFile(filepath.Clean(c.SCTRef))
			if err != nil {
				return fmt.Errorf("reading sct from file: %w", err)
			}
			v.CheckOpts.SCT = sct
		}

	default:
		// Do nothing. Neither keyRef, c.Sk, nor certRef were set - can happen for example when using Fulcio and TSA.
		// For an example see the TestAttachWithRFC3161Timestamp test in test/e2e_test.go.
	}
	v.CheckOpts.SigVerifier = pubKey
	return nil
}

// NewCheckOpts updates the signature verifierOpts by verifierOptions.
func NewCheckOpts(ctx context.Context, c *verify.VerifyCommand) (opts *cosign.CheckOpts, err error) {
	// initialize the cosign check options
	opts = &cosign.CheckOpts{}

	if c.CheckClaims {
		opts.ClaimVerifier = cosign.SimpleClaimVerifier
	}

	// If we are using signed timestamps, we need to load the TSA certificates
	if c.TSACertChainPath != "" || c.UseSignedTimestamps {
		tsaCertificates, err := cosign.GetTSACerts(ctx, c.TSACertChainPath, cosign.GetTufTargets)
		if err != nil {
			return nil, fmt.Errorf("unable to load TSA certificates: %w", err)
		}
		opts.TSACertificate = tsaCertificates.LeafCert
		opts.TSARootCertificates = tsaCertificates.RootCert
		opts.TSAIntermediateCertificates = tsaCertificates.IntermediateCerts
	}

	if !c.IgnoreTlog {
		if c.RekorURL == "" {
			c.RekorURL = defaultRekorURL
		}

		rekorClient, err := rekor.NewClient(c.RekorURL)
		if err != nil {
			return nil, fmt.Errorf("creating Rekor client: %w", err)
		}
		opts.RekorClient = rekorClient

		// This performs an online fetch of the Rekor public keys, but this is needed
		// for verifying tlog entries (both online and offline).
		opts.RekorPubKeys, err = cosign.GetRekorPubs(ctx)
		if err != nil {
			return nil, fmt.Errorf("getting Rekor public keys: %w", err)
		}
	}
	return opts, nil
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

func getVerifyCommandFromOpts(v *Verifier, opts *ratify.VerifyOptions) (*verify.VerifyCommand, error) {
	v.truststore.GetVerifyOpts(opts.Subject)
	return nil, nil
}

// staticLayerOpts builds the cosign options for static layer signatures.
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
