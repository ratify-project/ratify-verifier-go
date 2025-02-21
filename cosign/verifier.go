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
	// It includes various settings and parameters that influence the verification process.
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

	sig, signatureDescHash, err := getgSigandSigDesc(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get signature and signature descriptor: %w", err)
	}

	result := &ratify.VerificationResult{
		Verifier: v,
	}
	// TODO: update verify result
	_, err = cosign.VerifyImageSignature(ctx, sig, signatureDescHash, checkOpts)
	if err != nil {
		result.Err = err
		return result, nil
	}

	result.Description = "cosign signature verification succeeded"
	return result, nil
}

// getCheckOpts updates the signature verifierOpts by verifierOptions.
func getCheckOpts(ctx context.Context, vctx *verifycontextoptions.VerifyContext, s truststore.TrustStore) (opts *cosign.CheckOpts, err error) {
	// initialize the cosign check options
	opts = &cosign.CheckOpts{}

	if vctx.CheckClaims {
		opts.ClaimVerifier = cosign.SimpleClaimVerifier
	}

	// If we are using signed timestamps, we need to load the TSA certificates
	if vctx.TSACertChainPath != "" || vctx.UseSignedTimestamps {
		// TODO: update cosign get TSA certs
		tsaCertificates, err := cosign.GetTSACerts(ctx, vctx.TSACertChainPath, cosign.GetTufTargets)
		if err != nil {
			return nil, err
		}
		opts.TSACertificate = tsaCertificates.LeafCert
		opts.TSARootCertificates = tsaCertificates.RootCert
		opts.TSAIntermediateCertificates = tsaCertificates.IntermediateCerts
	}

	if !vctx.IgnoreTlog {
		rekorURL := defaultRekorURL
		if vctx.RekorURL != "" {
			rekorURL = vctx.RekorURL
		}

		rekorClient, err := rekor.GetRekorClient(rekorURL)
		if err != nil {
			return nil, err
		}
		opts.RekorClient = rekorClient

		// This performs an online fetch of the Rekor public keys, but this is needed
		// for verifying tlog entries (both online and offline).
		opts.RekorPubKeys, err = cosign.GetRekorPubs(ctx)
		if err != nil {
			return nil, err
		}
	}

	// Ignore Signed Certificate Timestamp if the flag is set or a key is provided
	if vctx.KeyRef == "" && !vctx.Sk && !vctx.IgnoreSCT {
		opts.CTLogPubKeys, err = cosign.GetCTLogPubs(ctx)
		if err != nil {
			return nil, err
		}
	}

	// TODO: update the os operation include by the cosign library
	var pubKey signature.Verifier = nil
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
		pubKey, err = signature.LoadVerifier(key, hashAlgorithm)
		if err != nil {
			return nil, err
		}
		// pkcs11Key, ok := pubKey.(*pkcs11key.Key)
		// if ok {
		// 	defer pkcs11Key.Close()
		// }
	case vctx.Sk:
		// TODO: support secure key
		// sk, err := pivkey.GetKeyWithSlot(vctx.Slot)
		// defer sk.Close()
		// if err != nil {
		// 	return nil, err
		// }
		// pubKey, err = sk.Verifier()
		// if err != nil {
		// 	return nil, err
		// }
	case vctx.CertRef != "":
		cert, err := s.GetCertificate(ctx, vctx.CertRef)
		if err != nil {
			return nil, err
		}
		switch {
		case vctx.CertChain == "" && opts.RootCerts == nil:
			// If no certChain and no CARoots are passed, the Fulcio root certificate will be used
			opts.RootCerts, err = fulcioroots.Get()
			if err != nil {
				return nil, err
			}
			opts.IntermediateCerts, err = fulcioroots.GetIntermediates()
			if err != nil {
				return nil, err
			}
			pubKey, err = cosign.ValidateAndUnpackCert(cert, opts)
			if err != nil {
				return nil, err
			}
		case vctx.CertChain != "":
			// Verify certificate with chain
			chain, err := s.GetCertChain(ctx, vctx.CertChain)
			if err != nil {
				return nil, err
			}
			pubKey, err = cosign.ValidateAndUnpackCertWithChain(cert, chain, opts)
			if err != nil {
				return nil, err
			}
		case opts.RootCerts != nil:
			// Verify certificate with root (and if given, intermediate) certificate
			pubKey, err = cosign.ValidateAndUnpackCert(cert, opts)
			if err != nil {
				return nil, err
			}
		default:
			return nil, err
		}

		// TODO: fix SCT support

		// if vctx.SCTRef != "" {
		// 	sct, err := os.ReadFile(filepath.Clean(vctx.SCTRef))
		// 	if err != nil {
		// 		return nil, err
		// 	}
		// 	opts.IgnoreSCT = vctx.IgnoreSCT
		// 	opts.SCT = sct
		// }

	default:
		// Do nothing. Neither keyRef, c.Sk, nor certRef were set - can happen for example when using Fulcio and TSA.
		// For an example see the TestAttachWithRFC3161Timestamp test in test/e2e_test.go.
	}
	opts.SigVerifier = pubKey
	opts.MaxWorkers = vctx.MaxWorkers

	return opts, nil
}

func getgSigandSigDesc(ctx context.Context, opts *ratify.VerifyOptions) (oci.Signature, v1.Hash, error) {
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

// getStaticLayerOpts builds the cosign options for static layer signatures.
func getStaticLayerOpts(desc ocispec.Descriptor) ([]static.Option, error) {
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
