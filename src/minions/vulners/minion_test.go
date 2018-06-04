//  Copyright 2018 Google LLC
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at

//        https://www.apache.org/licenses/LICENSE-2.0

//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//	limitations under the License.

package vulners

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAnalyzeFiles_local(t *testing.T) {
	m := NewMinion()
	resp, _ := m.AnalyzeFiles(nil, nil)

	for _, f := range resp.GetFindings() {
		print(f.GetVulnerableResources()[0].GetAdditionalInfo())
		print("\n")
		print(f.GetAdvisory().GetReference())
		print("\n")
	}
}

func TestListInitialInterests(t *testing.T) {
	m := NewMinion()
	foundDpkg := false
	interests, _ := m.ListInitialInterests(nil, nil)
	for _, i := range interests.GetInterests() {
		if i.GetPathRegexp() == "/var/lib/dpkg/status" {
			foundDpkg = true
		}
	}
	assert.True(t, foundDpkg)
}
