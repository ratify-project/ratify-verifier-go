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
	"crypto/x509"
	"errors"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	"github.com/stretchr/testify/assert"
	"oras.land/oras-go/v2/registry"
)

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

func TestStaticLayerOpts(t *testing.T) {
	tests := []struct {
		name          string
		desc          ocispec.Descriptor
		expectedOpts  []static.Option
		expectedError bool
	}{
		{
			name: "valid annotations with cert and chain",
			desc: ocispec.Descriptor{
				Annotations: map[string]string{
					static.CertificateAnnotationKey: "cert",
					static.ChainAnnotationKey:       "chain",
				},
			},
			expectedOpts: []static.Option{
				static.WithAnnotations(map[string]string{
					static.CertificateAnnotationKey: "cert",
					static.ChainAnnotationKey:       "chain",
				}),
				static.WithCertChain([]byte("cert"), []byte("chain")),
			},
			expectedError: false,
		},
		{
			name: "valid annotations with rekor bundle",
			desc: ocispec.Descriptor{
				Annotations: map[string]string{
					static.BundleAnnotationKey: `{"Payload":{"body":"body"}}`,
				},
			},
			expectedOpts: []static.Option{
				static.WithAnnotations(map[string]string{
					static.BundleAnnotationKey: `{"SignedEntryTimestamp":"timestamp","Payload":{"body":"body"}}`,
				}),
				static.WithBundle(&bundle.RekorBundle{
					Payload: bundle.RekorPayload{
						Body: "body",
					},
				}),
			},
			expectedError: false,
		},
		{
			name: "invalid rekor bundle",
			desc: ocispec.Descriptor{
				Annotations: map[string]string{
					static.BundleAnnotationKey: "invalid-bundle",
				},
			},
			expectedOpts:  nil,
			expectedError: true,
		},
		{
			name: "no annotations",
			desc: ocispec.Descriptor{
				Annotations: map[string]string{},
			},
			expectedOpts: []static.Option{
				static.WithAnnotations(map[string]string{}),
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, err := staticLayerOpts(tt.desc)
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, len(tt.expectedOpts), len(opts))
			}
		})
	}
}

// mockCertOptions is a mock implementation of CertOptions.
type mockCertOptions struct {
	getRootsShouldReturnError         bool
	getIntermediatesShouldReturnError bool
}

func (m *mockCertOptions) GetRoots() (*x509.CertPool, error) {
	if m.getRootsShouldReturnError {
		return nil, errors.New("failed to get roots")
	}
	return x509.NewCertPool(), nil
}

func (m *mockCertOptions) GetIntermediates() (*x509.CertPool, error) {
	if m.getIntermediatesShouldReturnError {
		return nil, errors.New("failed to get intermediates")
	}
	return x509.NewCertPool(), nil
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
