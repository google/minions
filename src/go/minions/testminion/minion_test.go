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

package testminion

import (
	"testing"

	pb "github.com/google/minions/proto/minions"
	"github.com/stretchr/testify/require"
)

func TestAnalyzeFiles_whenSetWantsVulnerable_returnsVulns(t *testing.T) {
	m := &Minion{paths: nil, wantsVuln: true}
	files := []*pb.File{file("/my/path")}

	req := &pb.AnalyzeFilesRequest{ScanId: "irrelevant_scan_id", Files: files}
	res, err := m.AnalyzeFiles(nil, req)

	require.NoError(t, err)
	require.Equal(t, "/my/path", res.GetFindings()[0].GetVulnerableResources()[0].GetPath())
}

func TestAnalyzeFiles_whenNotSetWantsVulnerable_returnsNoVuln(t *testing.T) {
	m := &Minion{paths: nil, wantsVuln: false}
	files := []*pb.File{file("/my/path")}

	req := &pb.AnalyzeFilesRequest{ScanId: "irrelevant_scan_id", Files: files}
	res, err := m.AnalyzeFiles(nil, req)

	require.NoError(t, err)
	require.Empty(t, res.GetFindings())
}

func file(name string) *pb.File {
	return &pb.File{
		Metadata: &pb.FileMetadata{
			Path: name,
		},
	}
}
