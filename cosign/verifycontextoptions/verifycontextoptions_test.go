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
	"testing"
)

func TestNewVerifyContextOptions(t *testing.T) {
	vco := NewVerifyContextOptions()
	if vco == nil {
		t.Fatalf("failed to init new verify context options")
	}
}

func TestGetVerifyOpts(t *testing.T) {
	vco := NewVerifyContextOptions().(*verifyContextOptions)

	// Test case: subjectRef not found
	_, err := vco.GetVerifyOpts("nonexistent")
	if err == nil || err.Error() != "failed to get verify options" {
		t.Fatalf("expected error, got nil")
	}

	// Test case: subjectRef found
	// expectedOpts := &VerifyContext{}
	// vco.optsMap["existent"] = expectedOpts
	// opts, err := vco.GetVerifyOpts("existent")
	// if err != nil || opts == nil {
	// 	t.Fatalf("failed to get a verify context option: %v", err)
	// }
}
