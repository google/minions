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
	"io/ioutil"
	"os"
	"testing"

	"github.com/google/minions/go/minions"
	pb "github.com/google/minions/proto/minions"
	"github.com/stretchr/testify/require"
)

func TestAnalyzeFiles_singleCall_returnsVulns(t *testing.T) {
	// This data matches the dpkg and os-release.1 testdata files.
	mockedRequest := buildMockVulnClientKey("Ubuntu", "18.04", []string{"fonts-sil-abyssinica 1.500-1 all", "mokutil 0.3.0-0ubuntu5 amd64"})
	mockResp := buildMockedAPIVulnResponse("fonts-sil-abyssinica")
	mockClient := &mockVulnerabilityClient{responses: map[string]*VulnResponse{mockedRequest: mockResp}}
	m := &Minion{apiClient: mockClient, state: minions.NewLocalStateManager()}

	// We send both files in a single call.
	files := []*pb.File{
		buildFile("/etc/os-release", "/testdata/os-release.1.txt", t),
		buildFile("/var/lib/dpkg/status", "/testdata/dpkg.txt", t),
	}

	req := &pb.AnalyzeFilesRequest{ScanId: "irrelevant_scan_id", Files: files}
	res, err := m.AnalyzeFiles(nil, req)
	require.NoError(t, err)
	packageSource := res.GetFindings()[0].GetVulnerableResources()[0].GetAdditionalInfo()
	require.Equal(t, "fonts-sil-abyssinica", packageSource)
	require.Equal(t, pb.Finding_SEVERITY_MEDIUM, res.GetFindings()[0].GetSeverity())
}

func TestAnalyzeFiles_osReleaseFirst_returnsVulns(t *testing.T) {
	mockedRequest := buildMockVulnClientKey("Ubuntu", "18.04", []string{"fonts-sil-abyssinica 1.500-1 all", "mokutil 0.3.0-0ubuntu5 amd64"})
	mockResp := buildMockedAPIVulnResponse("mokutil")
	mockClient := &mockVulnerabilityClient{responses: map[string]*VulnResponse{mockedRequest: mockResp}}
	m := &Minion{apiClient: mockClient, state: minions.NewLocalStateManager()}

	// Send first the OS release file
	scanID := "A_SCAN_ID"
	filesReq1 := []*pb.File{buildFile("/etc/os-release", "/testdata/os-release.1.txt", t)}
	req1 := &pb.AnalyzeFilesRequest{ScanId: scanID, Files: filesReq1}
	_, err := m.AnalyzeFiles(nil, req1)
	require.NoError(t, err)

	// Now send the DPKG file
	filesReq2 := []*pb.File{buildFile("/var/lib/dpkg/status", "/testdata/dpkg.txt", t)}
	req2 := &pb.AnalyzeFilesRequest{ScanId: scanID, Files: filesReq2}
	res, err := m.AnalyzeFiles(nil, req2)
	require.NoError(t, err)
	packageSource := res.GetFindings()[0].GetVulnerableResources()[0].GetAdditionalInfo()
	require.Equal(t, "mokutil", packageSource)
}

func TestAnalyzeFiles_dpkgFirst_returnsVulns(t *testing.T) {
	mockedRequest := buildMockVulnClientKey("Ubuntu", "18.04", []string{"fonts-sil-abyssinica 1.500-1 all", "mokutil 0.3.0-0ubuntu5 amd64"})
	mockResp := buildMockedAPIVulnResponse("mokutil")
	mockClient := &mockVulnerabilityClient{responses: map[string]*VulnResponse{mockedRequest: mockResp}}
	m := &Minion{apiClient: mockClient, state: minions.NewLocalStateManager()}

	scanID := "A_SCAN_ID"

	// First send the DPKG file
	filesReq2 := []*pb.File{buildFile("/var/lib/dpkg/status", "/testdata/dpkg.txt", t)}
	req2 := &pb.AnalyzeFilesRequest{ScanId: scanID, Files: filesReq2}
	_, err := m.AnalyzeFiles(nil, req2)
	require.NoError(t, err)

	// Send second the OS release file
	filesReq1 := []*pb.File{buildFile("/etc/os-release", "/testdata/os-release.1.txt", t)}
	req1 := &pb.AnalyzeFilesRequest{ScanId: scanID, Files: filesReq1}
	res, err := m.AnalyzeFiles(nil, req1)
	require.NoError(t, err)

	packageSource := res.GetFindings()[0].GetVulnerableResources()[0].GetAdditionalInfo()
	require.Equal(t, "mokutil", packageSource)
}

func TestListInitialInterests(t *testing.T) {
	paths := []string{"/var/lib/dpkg/status", "/etc/os-release", "/usr/lib/os-release", "/var/lib/rpm/Packages"}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			m := NewMinion("irrelevant")
			foundPath := false
			interests, _ := m.ListInitialInterests(nil, nil)
			for _, i := range interests.GetInterests() {
				if i.GetPathRegexp() == p {
					foundPath = true
				}
			}
			require.True(t, foundPath)
		})
	}
}

func buildFile(name string, path string, t *testing.T) *pb.File {
	// Keep the test simple since we know we only care about this.
	m := &pb.FileMetadata{
		Path: name,
	}
	basepath, err := os.Getwd()
	d, err := ioutil.ReadFile(basepath + path)
	require.NoError(t, err)
	f := &pb.File{
		Metadata: m,
		Data:     d,
	}
	return f
}
