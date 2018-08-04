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

package redis

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/phayes/permbits"

	pb "github.com/google/minions/proto/minions"
	"github.com/stretchr/testify/require"
)

func TestAnalyzeFiles_ubuntuConfig_returnsNoVuln(t *testing.T) {
	m := &Minion{}
	files := []*pb.File{buildFile("/etc/redis/redis.conf", "/testdata/redis.1.conf", t)}

	req := &pb.AnalyzeFilesRequest{ScanId: "irrelevant_scan_id", Files: files}
	res, err := m.AnalyzeFiles(nil, req)
	require.NoError(t, err)
	require.Empty(t, res.GetFindings())
}

func TestAnalyzeFiles_networkBindWithMultipleBind_returnsVuln(t *testing.T) {
	m := &Minion{}
	files := []*pb.File{buildFile("/etc/redis/redis.conf", "/testdata/redis.2.conf", t)}

	req := &pb.AnalyzeFilesRequest{ScanId: "irrelevant_scan_id", Files: files}
	res, err := m.AnalyzeFiles(nil, req)
	require.NoError(t, err)
	require.Equal(t, "MINIONS_REDIS_02", res.GetFindings()[0].GetAdvisory().GetReference())
}

func TestAnalyzeFiles_networkBindWithPassword_returnsNoVuln(t *testing.T) {
	m := &Minion{}
	files := []*pb.File{buildFile("/etc/redis/redis.conf", "/testdata/redis.3.conf", t)}

	req := &pb.AnalyzeFilesRequest{ScanId: "irrelevant_scan_id", Files: files}
	res, err := m.AnalyzeFiles(nil, req)
	require.NoError(t, err)
	require.Empty(t, res.GetFindings())
}

func TestAnalyzeFiles_networkBindWithPasswordAndSpaces_returnsNoVuln(t *testing.T) {
	m := &Minion{}
	files := []*pb.File{buildFile("/etc/redis/redis.conf", "/testdata/redis.5.conf", t)}

	req := &pb.AnalyzeFilesRequest{ScanId: "irrelevant_scan_id", Files: files}
	res, err := m.AnalyzeFiles(nil, req)
	require.NoError(t, err)
	require.Empty(t, res.GetFindings())
}

func TestAnalyzeFiles_networkBindWithoutPasswordWithSafeMode_returnsNoVuln(t *testing.T) {
	m := &Minion{}
	files := []*pb.File{buildFile("/etc/redis/redis.conf", "/testdata/redis.4.conf", t)}

	req := &pb.AnalyzeFilesRequest{ScanId: "irrelevant_scan_id", Files: files}
	res, err := m.AnalyzeFiles(nil, req)
	require.NoError(t, err)
	require.Empty(t, res.GetFindings())
}

func TestAnalyzeFiles_insecurePermissionsWithPassword_returnsVuln(t *testing.T) {
	m := &Minion{}
	f := buildFile("/etc/os-release", "/testdata/redis.3.conf", t)
	f = setWorldReadable(f)
	files := []*pb.File{f}

	req := &pb.AnalyzeFilesRequest{ScanId: "irrelevant_scan_id", Files: files}
	res, err := m.AnalyzeFiles(nil, req)
	require.NoError(t, err)
	require.Equal(t, "MINIONS_REDIS_01", res.GetFindings()[0].GetAdvisory().GetReference())
}

func TestAnalyzeFiles_insecurePermissionsWithoutPassword_returnsNoVuln(t *testing.T) {
	m := &Minion{}
	f := buildFile("/etc/os-release", "/testdata/redis.1.conf", t)
	setWorldReadable(f)
	files := []*pb.File{f}

	req := &pb.AnalyzeFilesRequest{ScanId: "irrelevant_scan_id", Files: files}
	res, err := m.AnalyzeFiles(nil, req)
	require.NoError(t, err)
	require.Empty(t, res.GetFindings())
}

func setWorldReadable(f *pb.File) *pb.File {
	// Change permissions to world readable.
	perm := os.FileMode(f.Metadata.Permissions)
	bits := permbits.PermissionBits(perm)
	bits.SetOtherRead(true)
	permbits.UpdateFileMode(&perm, bits)
	f.Metadata.Permissions = uint32(perm)
	return f
}

func buildFile(name string, path string, t *testing.T) *pb.File {
	// Setting defaults for config files (readable only to group and owner)
	pbtis := permbits.PermissionBits(0)
	pbtis.SetUserRead(true)
	pbtis.SetUserWrite(true)
	pbtis.SetGroupRead(true)
	fm := os.FileMode(0)
	permbits.UpdateFileMode(&fm, pbtis)

	m := &pb.FileMetadata{
		Path:        name,
		Permissions: uint32(fm.Perm()),
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
