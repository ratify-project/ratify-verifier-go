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
	"crypto/x509"
	"errors"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/ratify-project/ratify-go"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
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
		name          string
		repo          string
		opts          *cosign.CheckOpts
		keysMap       map[string]crypto.PublicKey
		certOpt       CertOptions
		expectedError bool
	}{
		{
			name: "key exists in keysMap",
			repo: "test-repo",
			opts: &cosign.CheckOpts{},
			keysMap: map[string]crypto.PublicKey{
				"test-repo": &priv.PublicKey,
			},
			certOpt:       &mockCertOptions{},
			expectedError: false,
		},
		{
			name:          "key does not exist in keysMap and cert options return roots and intermediates",
			repo:          "test-repo",
			opts:          &cosign.CheckOpts{},
			keysMap:       map[string]crypto.PublicKey{},
			certOpt:       &mockCertOptions{},
			expectedError: false,
		},
		{
			name:          "key does not exist in keysMap and cert options return error",
			repo:          "test-repo",
			opts:          &cosign.CheckOpts{},
			keysMap:       map[string]crypto.PublicKey{},
			certOpt:       &mockCertOptions{getRootsShouldReturnError: true},
			expectedError: true,
		},
		{
			name:          "key does not exist in keysMap and cert options return error",
			repo:          "test-repo",
			opts:          &cosign.CheckOpts{},
			keysMap:       map[string]crypto.PublicKey{},
			certOpt:       &mockCertOptions{getIntermediatesShouldReturnError: true},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := updateCheckOpts(tt.repo, tt.opts, tt.keysMap, tt.certOpt)
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if _, exists := tt.keysMap[tt.repo]; exists {
					assert.NotNil(t, tt.opts.SigVerifier)
				} else {
					assert.Nil(t, tt.opts.SigVerifier)
					assert.NotNil(t, tt.opts.RootCerts)
					assert.True(t, tt.opts.IgnoreSCT)
					assert.NotNil(t, tt.opts.IntermediateCerts)
				}
			}
		})
	}
}

func TestVerifier_Verify(t *testing.T) {
	testRepo := "test-registry/test-repo"
	testDigest1 := "sha256:cd0abf4135161b8aeb079b64b8215e433088d21463204771d070aadc52678aa0"
	testSubject := testRepo + "@" + testDigest1
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tests := []struct {
		name          string
		verifier      *Verifier
		verifyOptions *ratify.VerifyOptions
		mockStore     *mockStore
		expectedError bool
		expectedDesc  string
	}{
		{
			name: "successful keyless verification",
			verifier: &Verifier{
				name:    "test-verifier",
				keysMap: map[string]crypto.PublicKey{},
				CheckOpts: &cosign.CheckOpts{
					IgnoreTlog: true,
				},
			},
			verifyOptions: &ratify.VerifyOptions{
				Subject: testSubject,
				Store: &mockStore{
					FetchBlobContentFunc: func(ctx context.Context, repository string, desc ocispec.Descriptor) ([]byte, error) {
						return []byte(`{"critical":{"identity":{"docker-reference":"wabbitnetworks.azurecr.io/test/cosign-image"},"image":{"docker-manifest-digest":"sha256:623621b56649b5e0c2c7cf3ffd987932f8f9a5a01036e00d6f3ae9480087621c"},"type":"cosign container image signature"},"optional":null}`), nil
					},
					FetchImageManifestFunc: func(ctx context.Context, ref string, desc ocispec.Descriptor) (*ocispec.Manifest, error) {
						return &ocispec.Manifest{
							Layers: []ocispec.Descriptor{
								{
									MediaType: artifactTypeCosign,
									Digest:    digest.NewDigestFromEncoded(digest.SHA256, "d1226e36bc8502978324cb2cb2116c6aa48edb2ea8f15b1c6f6f256ed43388f6"),
									Annotations: map[string]string{
										"dev.cosignproject.cosign/signature": "MEUCIFBlKbxxg1Ni++g99jeWO8Of3g5L0Xd+qMzdqCZySQ8DAiEA3lcOJPJ1FQOahtWaRU0hG0XxFEsbcVx6SIyzYQMMR0A=",
										"dev.sigstore.cosign/bundle":         "{\"SignedEntryTimestamp\":\"MEUCIAIZfWhm9x2F7wil5dkWX+0+njT+FWXFr8AskDkiHpzoAiEApDk9STKcBJTkQ4qy9/8gn6ea2wduh3UjbLRnzZQa9gU=\",\"Payload\":{\"body\":\"eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiJkMTIyNmUzNmJjODUwMjk3ODMyNGNiMmNiMjExNmM2YWE0OGVkYjJlYThmMTViMWM2ZjZmMjU2ZWQ0MzM4OGY2In19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FVUNJRkJsS2J4eGcxTmkrK2c5OWplV084T2YzZzVMMFhkK3FNemRxQ1p5U1E4REFpRUEzbGNPSlBKMUZRT2FodFdhUlUwaEcwWHhGRXNiY1Z4NlNJeXpZUU1NUjBBPSIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlNVTnZSRU5EUVdsaFowRjNTVUpCWjBsVlVsWjFTa3A2T1VneWJGUldWMDgyTjFCdWMyZDBUWFJUYld4TmQwTm5XVWxMYjFwSmVtb3dSVUYzVFhjS1RucEZWazFDVFVkQk1WVkZRMmhOVFdNeWJHNWpNMUoyWTIxVmRWcEhWakpOVWpSM1NFRlpSRlpSVVVSRmVGWjZZVmRrZW1SSE9YbGFVekZ3WW01U2JBcGpiVEZzV2tkc2FHUkhWWGRJYUdOT1RXcE5kMDFxUlRKTlJGVjVUWHBCTUZkb1kwNU5hazEzVFdwRk1rMUVWWHBOZWtFd1YycEJRVTFHYTNkRmQxbElDa3R2V2tsNmFqQkRRVkZaU1V0dldrbDZhakJFUVZGalJGRm5RVVUzWlV0MU9IQnJOMmN5TDBsU2FGSjVNbEF2TWtoamMxTkNZMWcyUWxwb1QwTkpjMndLU0RBMVFWaHhTelZsUzBKR1R6QmxUU3RvU0hGeGFXbHRZVFJVYm5kNll6RnpUMjkwT0hSVVJuYzVlVVJFYlhod1RrdFBRMEZWVlhkblowWkNUVUUwUndwQk1WVmtSSGRGUWk5M1VVVkJkMGxJWjBSQlZFSm5UbFpJVTFWRlJFUkJTMEpuWjNKQ1owVkdRbEZqUkVGNlFXUkNaMDVXU0ZFMFJVWm5VVlZNYVZWRUNub3hSRzV2YURsVlRXZHBiMDh4ZEZsdU1IYzFTVUpWZDBoM1dVUldVakJxUWtKbmQwWnZRVlV6T1ZCd2VqRlphMFZhWWpWeFRtcHdTMFpYYVhocE5Ga0tXa1E0ZDBsQldVUldVakJTUVZGSUwwSkNXWGRHU1VWVFl6STVObHBZU21wWlZ6VkJXakl4YUdGWGQzVlpNamwwVFVOM1IwTnBjMGRCVVZGQ1p6YzRkd3BCVVVWRlNHMW9NR1JJUW5wUGFUaDJXakpzTUdGSVZtbE1iVTUyWWxNNWMySXlaSEJpYVRsMldWaFdNR0ZFUTBKcFVWbExTM2RaUWtKQlNGZGxVVWxGQ2tGblVqZENTR3RCWkhkQ01VRk9NRGxOUjNKSGVIaEZlVmw0YTJWSVNteHVUbmRMYVZOc05qUXphbmwwTHpSbFMyTnZRWFpMWlRaUFFVRkJRbWhzYVhRS1IweFZRVUZCVVVSQlJWbDNVa0ZKWjA5T2EyUndTSGx1Ykc4eWRFOXZZbkJ1Y2tSWFQwSTJTM2x3Y1d0V2RuUlZiVVpLSzFKVFZVZ3JTREJEU1VWTlNBcDBURFp0Y25nemVUTmxWV3R3ZGpJM2JsRk1VbFJhZDFkeVJuSTROR2QxUXpCNFVYZHdkVmxxVFVGdlIwTkRjVWRUVFRRNVFrRk5SRUV5WjBGTlIxVkRDazFCYTB4eVRuaHJWMlUwVHpGV2JFNDFPRTlqTkcxMlpGQjRjRFJhYUZGMFYwdFNNM0pGUmxCS2FXOXFOMWM1YkV3d1VIYzFiVlp5T1VaQ2VrZzJjMW9LY0dkSmVFRlFhamhKVUZaUFZWVlRVM1JUV0dnM1VsZHFkQ3RKVkVsNVYzQjNTWG8zVUd0MWFVOUZNSEJEUnpaSWRrZERkbXdyWmxScE1FMVFkbkpUVUFwb2NuSmxaV2M5UFFvdExTMHRMVVZPUkNCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2c9PSJ9fX19\",\"integratedTime\":1676524985,\"logIndex\":13452680,\"logID\":\"c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d\"}}",
										"dev.sigstore.cosign/certificate":    "-----BEGIN CERTIFICATE-----\nMIICoDCCAiagAwIBAgIURVuJJz9H2lTVWO67PnsgtMtSmlMwCgYIKoZIzj0EAwMw\nNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRl\ncm1lZGlhdGUwHhcNMjMwMjE2MDUyMzA0WhcNMjMwMjE2MDUzMzA0WjAAMFkwEwYH\nKoZIzj0CAQYIKoZIzj0DAQcDQgAE7eKu8pk7g2/IRhRy2P/2HcsSBcX6BZhOCIsl\nH05AXqK5eKBFO0eM+hHqqiima4Tnwzc1sOot8tTFw9yDDmxpNKOCAUUwggFBMA4G\nA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQULiUD\nz1Dnoh9UMgioO1tYn0w5IBUwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4Y\nZD8wIAYDVR0RAQH/BBYwFIESc296ZXJjYW5AZ21haWwuY29tMCwGCisGAQQBg78w\nAQEEHmh0dHBzOi8vZ2l0aHViLmNvbS9sb2dpbi9vYXV0aDCBiQYKKwYBBAHWeQIE\nAgR7BHkAdwB1AN09MGrGxxEyYxkeHJlnNwKiSl643jyt/4eKcoAvKe6OAAABhlit\nGLUAAAQDAEYwRAIgONkdpHynlo2tOobpnrDWOB6KypqkVvtUmFJ+RSUH+H0CIEMH\ntL6mrx3y3eUkpv27nQLRTZwWrFr84guC0xQwpuYjMAoGCCqGSM49BAMDA2gAMGUC\nMAkLrNxkWe4O1VlN58Oc4mvdPxp4ZhQtWKR3rEFPJioj7W9lL0Pw5mVr9FBzH6sZ\npgIxAPj8IPVOUUSStSXh7RWjt+ITIyWpwIz7PkuiOE0pCG6HvGCvl+fTi0MPvrSP\nhrreeg==\n-----END CERTIFICATE-----\n",
										"dev.sigstore.cosign/chain":          "-----BEGIN CERTIFICATE-----\nMIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMw\nKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y\nMjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3Jl\nLmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0C\nAQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV7\n7LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS\n0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYB\nBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjp\nKFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZI\nzj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJR\nnZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsP\nmygUY7Ii2zbdCdliiow=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMw\nKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y\nMTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3Jl\nLmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7\nXeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxex\nX69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92j\nYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRY\nwB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQ\nKsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCM\nWP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9\nTNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ\n-----END CERTIFICATE-----",
									},
								},
							},
						}, nil
					},
				},
				SubjectDescriptor: ocispec.Descriptor{
					Digest:    digest.NewDigestFromEncoded(digest.SHA256, "623621b56649b5e0c2c7cf3ffd987932f8f9a5a01036e00d6f3ae9480087621c"),
					MediaType: ocispec.MediaTypeImageManifest,
				},
			},
			expectedError: false,
			expectedDesc:  "cosign signature verification succeeded",
		},
		{
			name: "[WIP] successful verification",
			verifier: &Verifier{
				name: "test-verifier",
				keysMap: map[string]crypto.PublicKey{
					testSubject: &priv.PublicKey,
				},
				CheckOpts: &cosign.CheckOpts{
					IgnoreTlog: true,
				},
			},
			verifyOptions: &ratify.VerifyOptions{
				Subject: testSubject,
				Store: &mockStore{
					FetchBlobContentFunc: func(ctx context.Context, repository string, desc ocispec.Descriptor) ([]byte, error) {
						return []byte{}, nil
					},
					FetchImageManifestFunc: func(ctx context.Context, ref string, desc ocispec.Descriptor) (*ocispec.Manifest, error) {
						return &ocispec.Manifest{
							MediaType: artifactTypeCosign,
							Layers: []ocispec.Descriptor{
								{
									Annotations: map[string]string{
										static.SignatureAnnotationKey: "signature",
									},
								},
							},
						}, nil
					},
				},
				SubjectDescriptor: ocispec.Descriptor{
					MediaType: ocispec.MediaTypeImageManifest,
				},
			},
			expectedError: false,
			expectedDesc:  "cosign signature verification succeeded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			tt.verifier.CheckOpts.IgnoreTlog = false
			// create the rekor client
			tt.verifier.CheckOpts.RekorClient, _ = rekor.NewClient("https://rekor.sigstore.dev")
			// Fetches the Rekor public keys from the Rekor server
			tt.verifier.CheckOpts.RekorPubKeys, _ = cosign.GetRekorPubs(ctx)
			result, err := tt.verifier.Verify(ctx, tt.verifyOptions)
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, tt.expectedDesc, result.Description)
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
