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

package verifycontextoptions

import (
	"crypto"
	"fmt"
)

type VerifyContext struct {
	CheckClaims bool
	RekorURL    string
	IgnoreTlog  bool

	HashAlgorithm crypto.Hash
	KeyRef        string
	Sk            bool
	Slot          string
	SignatureRef  string

	CertRef              string
	CertIdentity         string
	CertIdentityRegexp   string
	CertOidcIssuer       string
	CertOidcIssuerRegexp string

	CAIntermediates string
	CARoots         string
	CertChain       string

	IgnoreSCT bool
	SCTRef    string

	UseSignedTimestamps bool
	TSACertChainPath    string

	// Max number of workers to use for parallel verification and the default value is 10
	MaxWorkers int
}

// VerifyContextOptions defines an interface for retrieving verification options
// for a given subject reference.
type VerifyContextOptions interface {
	// GetVerifyOpts retrieves the verification options for a given subject reference.
	GetVerifyOpts(subjectRef string) (*VerifyContext, error)
}

type verifyContextOptions struct {
	optsMap map[string]*VerifyContext
}

func New() VerifyContextOptions {
	return &verifyContextOptions{
		optsMap: make(map[string]*VerifyContext),
	}
}

// TODO: add a new with options to init the map with given options

func (v *verifyContextOptions) GetVerifyOpts(subjectRef string) (*VerifyContext, error) {
	opts, ok := v.optsMap[subjectRef]
	if !ok {
		return nil, fmt.Errorf("failed to get verify options")
	}
	return opts, nil
}
