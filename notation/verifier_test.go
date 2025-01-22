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
	"crypto/x509"
	"testing"

	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/ratify-project/ratify-go"
)

const (
	testVerifierName = "notation-1"
	verfierType      = "notation"
)

var notationSignatureArtifact = ocispec.Descriptor{
	ArtifactType: "application/vnd.cncf.notary.signature",
	MediaType:    "application/vnd.oci.image.manifest.v1+json",
}

type mockTrustStore struct{}

func (m *mockTrustStore) GetCertificates(ctx context.Context, storeType truststore.Type, namedStore string) ([]*x509.Certificate, error) {
	return nil, nil
}

func TestNewVerifier(t *testing.T) {
	opts := &NewVerifierOptions{
		Name: testVerifierName,
		TrustPolicyDoc: &trustpolicy.Document{
			Version: "1.0",
			TrustPolicies: []trustpolicy.TrustPolicy{
				{
					Name:           "default",
					RegistryScopes: []string{"*"},
					SignatureVerification: trustpolicy.SignatureVerification{
						VerificationLevel: "strict",
					},
					TrustStores:       []string{"ca:cert"},
					TrustedIdentities: []string{"*"},
				},
			},
		},
		TrustStore: &mockTrustStore{},
	}
	verifier, err := NewVerifier(opts)
	if err != nil || verifier == nil {
		t.Fatalf("failed to create a new verifier: %v", err)
	}
	if _, ok := interface{}(verifier).(ratify.Verifier); !ok {
		t.Fatalf("verifier does not implement ratify.Verifier")
	}

	if verifier.Name() != testVerifierName {
		t.Fatalf("unexpected verifier name: %s, expect: %s", verifier.Name(), testVerifierName)
	}
	if verifier.Type() != verfierType {
		t.Fatalf("unexpected verifier type: %s", verifier.Type())
	}

	if !verifier.Verifiable(notationSignatureArtifact) {
		t.Fatalf("unexpected artifact type: %s", notationSignatureArtifact.ArtifactType)
	}
}
