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
	"encoding/json"
	"errors"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/ratify-project/ratify-go"
	"github.com/ratify-project/ratify-verifier-go/cosign/truststore"
	"github.com/ratify-project/ratify-verifier-go/cosign/verifycontextoptions"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
)

var (
	testRepo    = "test-registry/test-repo"
	testDigest1 = "sha256:cd0abf4135161b8aeb079b64b8215e433088d21463204771d070aadc52678aa0"
)

func TestNewVerifier(t *testing.T) {
	opts := &VerifierOptions{
		Name:                 "test-verifier",
		VerifyContextOptions: verifycontextoptions.NewVerifyContextOptions(),
		Truststore:           truststore.NewTrustStore(),
	}

	verifier, err := NewVerifier(opts)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if verifier.name != opts.Name {
		t.Errorf("expected name %v, got %v", opts.Name, verifier.name)
	}

	if verifier.verifyContextOptions != opts.VerifyContextOptions {
		t.Errorf("expected verifyContextOptions %v, got %v", opts.VerifyContextOptions, verifier.verifyContextOptions)
	}

	if verifier.truststore != opts.Truststore {
		t.Errorf("expected truststore %v, got %v", opts.Truststore, verifier.truststore)
	}
}

func TestVerifier_Name(t *testing.T) {
	verifier := &Verifier{name: "test-verifier"}
	if verifier.Name() != "test-verifier" {
		t.Errorf("expected name %v, got %v", "test-verifier", verifier.Name())
	}
}

func TestVerifier_Type(t *testing.T) {
	verifier := &Verifier{}
	if verifier.Type() != cosignVerifierType {
		t.Errorf("expected type %v, got %v", cosignVerifierType, verifier.Type())
	}
}

func TestVerifier_Verifiable(t *testing.T) {
	verifier := &Verifier{}
	artifact := ocispec.Descriptor{
		ArtifactType: artifactTypeCosign,
		MediaType:    ocispec.MediaTypeImageManifest,
	}

	if !verifier.Verifiable(artifact) {
		t.Errorf("expected artifact to be verifiable")
	}

	artifact.ArtifactType = "invalid-type"
	if verifier.Verifiable(artifact) {
		t.Errorf("expected artifact to be not verifiable")
	}
}

func TestVerifier_Verify(t *testing.T) {
	verifier := &Verifier{
		verifyContextOptions: verifycontextoptions.NewVerifyContextOptions(),
		truststore:           truststore.NewTrustStore(),
	}

	ctx := context.Background()
	opts := &ratify.VerifyOptions{
		Repository: "test-repo",
		SubjectDescriptor: ocispec.Descriptor{
			Digest: digest.Digest(testDigest1),
		},
	}

	result, err := verifier.Verify(ctx, opts)
	if err == nil {
		t.Errorf("expected error, got nil")
	}

	if result != nil {
		t.Errorf("expected result to be nil, got %v", result)
	}
}

func TestGetCheckOpts(t *testing.T) {
	ctx := context.Background()
	vctx := &verifycontextoptions.VerifyContext{}
	s := truststore.NewTrustStore()

	opts, err := getCheckOpts(ctx, vctx, s)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if opts == nil {
		t.Errorf("expected opts to be non-nil")
	}
}

// func TestGetSignatureAndHash(t *testing.T) {
// 	ctx := context.Background()
// 	opts := &ratify.VerifyOptions{
// 		Store:      nil,
// 		Repository: "test-repo",
// 		ArtifactDescriptor: ocispec.Descriptor{
// 			Digest: digest.Digest(testDigest1),
// 		},
// 	}

// 	sig, hash, err := getSignatureAndHash(ctx, opts)
// 	if err == nil {
// 		t.Errorf("expected error, got nil")
// 	}

// 	if sig != nil {
// 		t.Errorf("expected sig to be nil, got %v", sig)
// 	}

// 	if hash != (v1.Hash{}) {
// 		t.Errorf("expected hash to be empty, got %v", hash)
// 	}
// }

func TestGetStaticLayerOpts(t *testing.T) {
	desc := ocispec.Descriptor{
		Annotations: map[string]string{
			static.CertificateAnnotationKey: "cert",
			static.ChainAnnotationKey:       "chain",
			static.BundleAnnotationKey:      `{"signedEntryTimestamp":"test"}`,
		},
	}

	opts, err := getStaticLayerOpts(desc)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(opts) == 0 {
		t.Errorf("expected opts to be non-empty")
	}
}

func TestGetSignatureBlobDesc(t *testing.T) {
	ctx := context.Background()
	store := &mockStore{}
	repo := "test-repo"
	artifactDesc := ocispec.Descriptor{}

	descs, err := getSignatureBlobDesc(ctx, store, repo, artifactDesc)
	if err == nil {
		t.Errorf("expected error, got nil")
	}

	if descs != nil {
		t.Errorf("expected descs to be nil, got %v", descs)
	}
}

// func TestGetKeylessVerifier(t *testing.T) {
// 	ctx := context.Background()
// 	cert := &x509.Certificate{}
// 	vctx := &verifycontextoptions.VerifyContext{
// 		CertVerifyOptions: verifycontextoptions.CertVerifyOptions{},
// 	}
// 	s := truststore.NewTrustStore()
// 	opts := &cosign.CheckOpts{}

// 	t.Run("CertChainEmptyAndRootCertsNil", func(t *testing.T) {
// 		vctx.CertVerifyOptions.CertChain = ""
// 		opts.RootCerts = nil

// 		verifier, err := getKeylessVerifier(ctx, cert, vctx, s, opts)
// 		if err != nil {
// 			t.Fatalf("expected no error, got %v", err)
// 		}
// 		if verifier == nil {
// 			t.Errorf("expected verifier to be non-nil")
// 		}
// 	})

// 	t.Run("CertChainNotEmpty", func(t *testing.T) {
// 		vctx.CertVerifyOptions.CertChain = "test-chain"

// 		// s.GetCertChain = func(ctx context.Context, certChain string) ([]*x509.Certificate, error) {
// 		// 	return []*x509.Certificate{cert}, nil
// 		// }

// 		verifier, err := getKeylessVerifier(ctx, cert, vctx, s, opts)
// 		if err != nil {
// 			t.Fatalf("expected no error, got %v", err)
// 		}
// 		if verifier == nil {
// 			t.Errorf("expected verifier to be non-nil")
// 		}
// 	})

// 	t.Run("CARootsNotNil", func(t *testing.T) {
// 		vctx.CertVerifyOptions.CARoots = &x509.CertPool{}

// 		verifier, err := getKeylessVerifier(ctx, cert, vctx, s, opts)
// 		if err != nil {
// 			t.Fatalf("expected no error, got %v", err)
// 		}
// 		if verifier == nil {
// 			t.Errorf("expected verifier to be non-nil")
// 		}
// 	})

// 	t.Run("InvalidCertificateOptions", func(t *testing.T) {
// 		vctx.CertVerifyOptions = verifycontextoptions.CertVerifyOptions{}

// 		verifier, err := getKeylessVerifier(ctx, cert, vctx, s, opts)
// 		if err == nil {
// 			t.Errorf("expected error, got nil")
// 		}
// 		if verifier != nil {
// 			t.Errorf("expected verifier to be nil, got %v", verifier)
// 		}
// 	})
// }

// mockStore is a mock implementation of ratify.Store.
type mockStore struct {
	manifest      *ocispec.Manifest
	manifestBytes []byte
	signatureBlob []byte
}

func (m *mockStore) Name() string {
	return "mock-store-name"
}

func (m *mockStore) ListReferrers(_ context.Context, _ string, _ []string, _ func(referrers []ocispec.Descriptor) error) error {
	return nil
}

func (m *mockStore) FetchBlob(_ context.Context, _ string, _ ocispec.Descriptor) ([]byte, error) {
	if m.signatureBlob == nil {
		return nil, errors.New("signature blob not initialized")
	}
	return m.signatureBlob, nil
}

func (m *mockStore) FetchManifest(_ context.Context, _ string, _ ocispec.Descriptor) ([]byte, error) {
	if m.manifest == nil && m.manifestBytes == nil {
		return nil, errors.New("image manifest not initialized")
	}
	if m.manifestBytes != nil {
		return m.manifestBytes, nil
	}
	return json.Marshal(m.manifest)
}

func (m *mockStore) Resolve(_ context.Context, _ string) (ocispec.Descriptor, error) {
	return ocispec.Descriptor{}, nil
}
