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
	"crypto/x509"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio"
)

type CertOptions interface {
	// GetRoots retrieves the root certificate for the given subject.
	GetRoots() (*x509.CertPool, error)

	// GetIntermediate retrieves the intermediate certificate for the given subject.
	GetIntermediates() (*x509.CertPool, error)
}

type DefaultCertOptions struct{}

func (d *DefaultCertOptions) GetRoots() (*x509.CertPool, error) {
	return fulcio.GetRoots()
}

func (d *DefaultCertOptions) GetIntermediates() (*x509.CertPool, error) {
	return fulcio.GetIntermediates()
}
