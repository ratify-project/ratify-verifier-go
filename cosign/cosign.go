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
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	ratify "github.com/ratify-project/ratify-go"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/util"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
)

type cosignVerifierOption struct { // nolint: revive
	// requireSignedTimestamps requires RFC3161 timestamps to verify
	// short-lived certificates
	requireSignedTimestamps bool
	// signedTimestampThreshold is the minimum number of verified
	// RFC3161 timestamps in a bundle
	signedTimestampThreshold int
	// requireIntegratedTimestamps requires log entry integrated timestamps to
	// verify short-lived certificates
	requireIntegratedTimestamps bool
	// integratedTimeThreshold is the minimum number of log entry
	// integrated timestamps in a bundle
	integratedTimeThreshold int
	// requireTlogEntries requires log inclusion proofs in a bundle
	requireTlogEntries bool
	// tlogEntriesThreshold is the minimum number of verified inclusion
	// proofs in a bundle
	tlogEntriesThreshold int
}

// TODO: update to be trustedMaterialOptions
type trustedMaterialOption struct {
	trustedPublicKey    string
	trustedrootJSONpath string
	tufRootURL          string
	tufTrustedRoot      string
}

// TODO: need to be decoupled as artifactOptions and policyOptions
type trustedPolicyOption struct {
	artifact                string
	artifactDigest          string
	artifactDigestAlgorithm string
	expectedOIDIssuer       string
	expectedOIDIssuerRegex  string
	expectedSAN             string
	expectedSANRegex        string
}

// prepareVerifierOptions returns the verifier options for the verifier.
func prepareVerifierOptions(opts *cosignVerifierOption) []verify.VerifierOption {
	verifierOptions := []verify.VerifierOption{}
	if opts.requireSignedTimestamps {
		verifierOptions = append(verifierOptions, verify.WithSignedCertificateTimestamps(opts.signedTimestampThreshold))
	}

	if opts.requireIntegratedTimestamps {
		verifierOptions = append(verifierOptions, verify.WithObserverTimestamps(opts.integratedTimeThreshold))
	}

	if opts.requireTlogEntries {
		verifierOptions = append(verifierOptions, verify.WithTransparencyLog(opts.tlogEntriesThreshold))
	}
	return verifierOptions
}

// TODO: implement the trusted material resolver
// prepareTrustedMaterial returns the trusted material for the verifier.
func prepareTrustedMaterial(ctx context.Context, opts *trustedMaterialOption) (root.TrustedMaterial, error) {
	var trustedMaterial = make(root.TrustedMaterialCollection, 0)
	var trustedRootJSON []byte
	var err error

	if opts.tufRootURL != "" {
		tufOpts := tuf.DefaultOptions()
		tufOpts.RepositoryBaseURL = opts.tufRootURL
		fetcher := fetcher.DefaultFetcher{}
		fetcher.SetHTTPUserAgent(util.ConstructUserAgent())
		tufOpts.Fetcher = &fetcher

		// Load the tuf root.json if provided, if not use public good
		if opts.tufTrustedRoot != "" {
			// TODO: update the FS store
			rb, err := os.ReadFile(opts.tufTrustedRoot)
			if err != nil {
				return nil, fmt.Errorf("failed to read %s: %w",
					opts.tufTrustedRoot, err)
			}
			tufOpts.Root = rb
		}

		client, err := tuf.New(tufOpts)
		if err != nil {
			return nil, err
		}
		trustedRootJSON, err = client.GetTarget("trusted_root.json")
		if err != nil {
			return nil, err
		}
	} else if opts.trustedrootJSONpath != "" {
		// TODO: update the FS store
		trustedRootJSON, err = os.ReadFile(opts.trustedrootJSONpath)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w",
				opts.trustedrootJSONpath, err)
		}
	}

	if len(trustedRootJSON) > 0 {
		var trustedRoot *root.TrustedRoot
		trustedRoot, err = root.NewTrustedRootFromJSON(trustedRootJSON)
		if err != nil {
			return nil, err
		}
		trustedMaterial = append(trustedMaterial, trustedRoot)
	}
	if opts.trustedPublicKey != "" {
		// TODO: update the FS store
		pemBytes, err := os.ReadFile(opts.trustedPublicKey)
		if err != nil {
			return nil, err
		}
		pemBlock, _ := pem.Decode(pemBytes)
		if pemBlock == nil {
			return nil, errors.New("failed to decode pem block")
		}
		pubKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
		if err != nil {
			return nil, err
		}
		trustedMaterial = append(trustedMaterial, trustedPublicKeyMaterial(pubKey))
	}

	if len(trustedMaterial) == 0 {
		return nil, errors.New("no trusted material provided")
	}
	return trustedMaterial, nil
}

type nonExpiringVerifier struct {
	signature.Verifier
}

func (*nonExpiringVerifier) ValidAtTime(_ time.Time) bool {
	return true
}

func trustedPublicKeyMaterial(pk crypto.PublicKey) *root.TrustedPublicKeyMaterial {
	return root.NewTrustedPublicKeyMaterial(func(string) (root.TimeConstrainedVerifier, error) {
		verifier, err := signature.LoadECDSAVerifier(pk.(*ecdsa.PublicKey), crypto.SHA256)
		if err != nil {
			return nil, err
		}
		return &nonExpiringVerifier{verifier}, nil
	})
}

// prepareSignedEntity returns the bundle for the verifier.
func prepareSignedEntity(_ ocispec.Descriptor, minBundleVersion string) (verify.SignedEntity, error) {
	// TODO: update the FS store
	b, err := bundle.LoadJSONFromPath(resolveBundlePath())
	if err != nil {
		return nil, err
	}

	if minBundleVersion != "" {
		if !b.MinVersion(minBundleVersion) {
			return nil, fmt.Errorf("bundle is not of minimum version %s", minBundleVersion)
		}
	}
	return b, nil
}

// TODO: need a Multiplexer interacts with the policy builder component policyOptions
// preparePolicyBuilder returns the policy builder for the verifier.
func preparePolicyBuilder(ctx context.Context, opts *trustedPolicyOption) (verify.PolicyBuilder, error) {
	var identityPolicies []verify.PolicyOption
	var artifactPolicy verify.ArtifactPolicyOption

	certID, err := verify.NewShortCertificateIdentity(opts.expectedOIDIssuer, opts.expectedOIDIssuerRegex, opts.expectedSAN, opts.expectedSANRegex)
	if err != nil {
		return verify.PolicyBuilder{}, err
	}
	identityPolicies = append(identityPolicies, verify.WithCertificateIdentity(certID))

	if opts.artifactDigest != "" { //nolint:gocritic
		artifactDigestBytes, err := hex.DecodeString(opts.artifactDigest)
		if err != nil {
			return verify.PolicyBuilder{}, err
		}
		artifactPolicy = verify.WithArtifactDigest(opts.artifactDigestAlgorithm, artifactDigestBytes)
	} else if opts.artifact != "" {
		file, err := os.Open(opts.artifact)
		if err != nil {
			return verify.PolicyBuilder{}, err
		}
		artifactPolicy = verify.WithArtifact(file)
	} else {
		artifactPolicy = verify.WithoutArtifactUnsafe()
		fmt.Fprintf(os.Stderr, "No artifact provided, skipping artifact verification. This is unsafe!\n")
	}
	return verify.NewPolicy(artifactPolicy, identityPolicies...), nil
}

// TODO: implement the bundle path resolver
func resolveBundlePath() string {
	return ""
}

// TODO: implement the trustpolicy resolver
func resolveTrustPolicy(_ ocispec.Descriptor) (*trustedPolicyOption, error) {
	return nil, nil
}

func getSignatureBlobDesc(ctx context.Context, store ratify.Store, repo string, artifactDesc ocispec.Descriptor) (ocispec.Descriptor, error) {
	manifestBytes, err := store.FetchManifest(ctx, repo, artifactDesc)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("failed to fetch manifest for artifact: %w", err)
	}

	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("failed to unmarshal manifest: %w", err)
	}

	if len(manifest.Layers) != 1 {
		return ocispec.Descriptor{}, fmt.Errorf("notation signature manifest requries exactly one signature envelope blob, got %d", len(manifest.Layers))
	}

	return manifest.Layers[0], nil
}
