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
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/stretchr/testify/assert"
	"oras.land/oras-go/v2/registry"
)

func TestNewVerifier(t *testing.T) {
	tests := []struct {
		name    string
		options *VerifierOptions
		wantErr bool
	}{
		{
			name: "valid options",
			options: &VerifierOptions{
				Name: "test-verifier",
				KeysMap: map[string]crypto.PublicKey{
					"test-repo": nil, // Replace with a valid public key for real tests
				},
				CheckOpts: &cosign.CheckOpts{},
			},
			wantErr: false,
		},
		// {
		// 	name: "missing name",
		// 	options: &VerifierOptions{
		// 		KeysMap: map[string]crypto.PublicKey{
		// 			"test-repo": nil, // Replace with a valid public key for real tests
		// 		},
		// 		CheckOpts: &cosign.CheckOpts{},
		// 	},
		// 	wantErr: true,
		// }
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier, err := NewVerifier(tt.options)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, verifier)
				assert.Equal(t, tt.options.Name, verifier.name)
				assert.Equal(t, tt.options.KeysMap, verifier.keysMap)
				assert.Equal(t, tt.options.CheckOpts, verifier.CheckOpts)
			}
		})
	}
}

func TestVerifier_Name(t *testing.T) {
	tests := []struct {
		name     string
		verifier *Verifier
		want     string
	}{
		{
			name: "valid name",
			verifier: &Verifier{
				name: "test-verifier",
			},
			want: "test-verifier",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.verifier.Name()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestVerifier_Type(t *testing.T) {
	tests := []struct {
		name     string
		verifier *Verifier
		want     string
	}{
		{
			name:     "valid type",
			verifier: &Verifier{},
			want:     cosignVerifierType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.verifier.Type()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestVerifier_Verifiable(t *testing.T) {
	tests := []struct {
		name     string
		artifact ocispec.Descriptor
		want     bool
	}{
		{
			name: "valid cosign signature",
			artifact: ocispec.Descriptor{
				ArtifactType: artifactTypeCosign,
				MediaType:    ocispec.MediaTypeImageManifest,
			},
			want: true,
		},
		{
			name: "invalid artifact type",
			artifact: ocispec.Descriptor{
				ArtifactType: "invalid-type",
				MediaType:    ocispec.MediaTypeImageManifest,
			},
			want: false,
		},
		{
			name: "invalid media type",
			artifact: ocispec.Descriptor{
				ArtifactType: artifactTypeCosign,
				MediaType:    "invalid-media-type",
			},
			want: false,
		},
		{
			name: "both artifact type and media type invalid",
			artifact: ocispec.Descriptor{
				ArtifactType: "invalid-type",
				MediaType:    "invalid-media-type",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Verifier{}
			got := v.Verifiable(tt.artifact)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetSignatureBlobDesc(t *testing.T) {
	tests := []struct {
		name          string
		store         *mockStore
		artifactRef   registry.Reference
		artifactDesc  ocispec.Descriptor
		expectedError bool
		expectedLen   int
	}{
		{
			name: "successful fetch with cosign signature layer",
			store: &mockStore{
				FetchImageManifestFunc: func(ctx context.Context, ref string, desc ocispec.Descriptor) (*ocispec.Manifest, error) {
					return &ocispec.Manifest{
						Layers: []ocispec.Descriptor{
							{
								MediaType: artifactTypeCosign,
							},
						},
					}, nil
				},
			},
			artifactRef: registry.Reference{
				Registry:   "test-registry",
				Repository: "test-repo",
			},
			artifactDesc: ocispec.Descriptor{
				MediaType: ocispec.MediaTypeImageManifest,
			},
			expectedError: false,
			expectedLen:   1,
		},
		{
			name: "successful fetch without cosign signature layer",
			store: &mockStore{
				FetchImageManifestFunc: func(ctx context.Context, ref string, desc ocispec.Descriptor) (*ocispec.Manifest, error) {
					return &ocispec.Manifest{
						Layers: []ocispec.Descriptor{
							{
								MediaType: "other-media-type",
							},
						},
					}, nil
				},
			},
			artifactRef: registry.Reference{
				Registry:   "test-registry",
				Repository: "test-repo",
			},
			artifactDesc: ocispec.Descriptor{
				MediaType: ocispec.MediaTypeImageManifest,
			},
			expectedError: false,
			expectedLen:   0,
		},
		{
			name: "failed to fetch image manifest",
			store: &mockStore{
				FetchImageManifestFunc: func(ctx context.Context, ref string, desc ocispec.Descriptor) (*ocispec.Manifest, error) {
					return nil, errors.New("failed to fetch image manifest")
				},
			},
			artifactRef: registry.Reference{
				Registry:   "test-registry",
				Repository: "test-repo",
			},
			artifactDesc: ocispec.Descriptor{
				MediaType: ocispec.MediaTypeImageManifest,
			},
			expectedError: true,
			expectedLen:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			layers, err := getSignatureBlobDesc(ctx, tt.store, tt.artifactRef, tt.artifactDesc)
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, layers, tt.expectedLen)
			}
		})
	}
}

func TestUpdateRepoSigVerifierKeys(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tests := []struct {
		name    string
		repo    string
		keysMap map[string]crypto.PublicKey
		wantErr bool
	}{
		{
			name: "successful key update",
			repo: "test-repo",
			keysMap: map[string]crypto.PublicKey{
				"test-repo": &priv.PublicKey,
			},
			wantErr: false,
		},
		{
			name:    "key not found",
			repo:    "non-existent-repo",
			keysMap: map[string]crypto.PublicKey{},
			wantErr: true,
		},
		{
			name: "failed to load verifier",
			repo: "test-repo",
			keysMap: map[string]crypto.PublicKey{
				"test-repo": nil,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &cosign.CheckOpts{
				SigVerifier: nil,
			}
			err := updateRepoSigVerifierKeys(tt.repo, opts, tt.keysMap)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, opts.SigVerifier)
			}
		})
	}
}

// mockStore is a mock implementation of ratify.Store.
type mockStore struct {
	imageManifest          *ocispec.Manifest
	signatureBlob          []byte
	FetchBlobContentFunc   func(ctx context.Context, repository string, desc ocispec.Descriptor) ([]byte, error)
	FetchImageManifestFunc func(ctx context.Context, ref string, desc ocispec.Descriptor) (*ocispec.Manifest, error)
}

func (m *mockStore) Name() string {
	return "mock-store-name"
}

func (m *mockStore) ListReferrers(_ context.Context, _ string, _ []string, _ func(referrers []ocispec.Descriptor) error) error {
	return nil
}

func (m *mockStore) FetchBlobContent(_ context.Context, _ string, _ ocispec.Descriptor) ([]byte, error) {
	if m.FetchBlobContentFunc != nil {
		return m.FetchBlobContentFunc(context.Background(), "", ocispec.Descriptor{})
	}
	if m.signatureBlob == nil {
		return nil, errors.New("signature blob not initialized")
	}
	return m.signatureBlob, nil
}

func (m *mockStore) FetchImageManifest(_ context.Context, _ string, _ ocispec.Descriptor) (*ocispec.Manifest, error) {
	if m.FetchImageManifestFunc != nil {
		return m.FetchImageManifestFunc(context.Background(), "", ocispec.Descriptor{})
	}
	if m.imageManifest == nil {
		return nil, errors.New("image manifest not initialized")
	}
	return m.imageManifest, nil
}

func (m *mockStore) Resolve(_ context.Context, _ string) (ocispec.Descriptor, error) {
	return ocispec.Descriptor{}, nil
}
