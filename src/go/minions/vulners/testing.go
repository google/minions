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
	"fmt"
	"strings"
)

type mockVulnerabilityClient struct {
	// We make our lives MUCH easier by accepting a tiny chance of mistakes and just
	// concatenating everything here - so the map key is the concat of version, os and packages.
	responses map[string]*VulnResponse
}

func (m *mockVulnerabilityClient) GetVulnerabilitiesForPackages(version string, os string, packages []string) (*VulnResponse, error) {
	key := buildMockVulnClientKey(version, os, packages)
	resp, found := m.responses[key]
	if !found {
		return nil, fmt.Errorf("could not find the request in our mock: %s", key)
	}
	return resp, nil
}

// buildMockVulnClientKey is a helper function to build an appropriate key to load the mock.
func buildMockVulnClientKey(version string, os string, packages []string) string {
	pkgs := strings.Join(packages, "")
	return strings.Join([]string{version, os, pkgs}, "/")
}

func buildMockedAPIVulnResponse(pkg string) *VulnResponse {
	pkgs := make(map[string]map[string][]vulnPackage)
	advisories := make(map[string][]vulnPackage)
	advisories["ADVISORY"] = []vulnPackage{vulnPackage{Package: pkg}}
	pkgs[pkg] = advisories
	data := vulnResponseData{Packages: pkgs}
	return &VulnResponse{Result: "ok", Data: data}
}
