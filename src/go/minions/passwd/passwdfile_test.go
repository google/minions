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

package passwdfile

import (
	"os"
	"reflect"
	"testing"
	"time"
)

// TODO(zbylut): check for specific Findings in the tests below after we have
// agreed upon a specific Finding format.

// TestListingInterests checks if the Minion returns the expected number of
// Interests.
func TestListingInterests(t *testing.T) {
	ctx := context.Background()
	mux := rpc.NewServeMux()
	srv := rpctest.NewServer(mux)
	defer srv.Close()

	var minion Minion
	response, err := minion.ListInitialInterests(ctx, &pb.ListInitialInterestsRequest{})
	if err != nil {
		t.Errorf("ListInitialInterests() unexpected error: %v", err)
	} else if len(response.GetInterests()) != 2 {
		t.Errorf("ListInitialInterests(): want 2 Interest, got %d", len(response.GetInterests()))
	}
}

// TestAnalyzingFiles checks if correct number of Findings is returned both
// /etc/passwd and /etc/shadow files.
func TestAnalyzingFiles(t *testing.T) {
	ctx := context.Background()
	var minion Minion

	request := &pb.AnalyzeFilesRequest{
		Files: []*pb.File{
			&pb.File{
				Metadata: &pb.FileMetadata{
					Path:        "/etc/passwd",
					Permissions: 0777,
				},
				Data: []byte("empty::3:3:nopw:foo:/bin/zsh\n"),
			},
			&pb.File{
				Metadata: &pb.FileMetadata{
					Path:        "/etc/shadow",
					Permissions: 0,
				},
				Data: []byte("weak:$1$salt$hash:1:2:3:4:::\n"),
			},
			&pb.File{
				Metadata: &pb.FileMetadata{
					Path: "extra_file",
				},
				Data: []byte("this minion shouldn't be interested in this file"),
			},
		},
	}

	res, err := minion.AnalyzeFiles(ctx, request)
	if err != nil {
		t.Errorf("AnalyzeFiles() returned unexpected error %v", err)
	} else if len(res.GetFindings()) != 3 {
		t.Errorf("AnalyzeFiles(): want 3 Findings, got %d (%v)", len(res.GetFindings()), res.GetFindings())
	}

	if len(res.GetNewInterests()) != 0 {
		t.Errorf("AnalyzeFiles() returned unexpected NewInterests: %v", res.GetNewInterests())
	}
}

// TestPasswdAnalyzing checks if the AnalyzePasswd method is returning
// the correct number of findings or errors.
func TestPasswdAnalyzing(t *testing.T) {
	malformedTest := &pb.File{Data: []byte("very malformed file")}

	if _, err := AnalyzePasswd(malformedTest); err == nil {
		t.Errorf("AnalyzePasswd(%v): expected error, got nil", malformedTest)
	}

	manyFindingsTest := &pb.File{
		Data: []byte("backdoor:x:0:2:suprise:/root:/bin/sh\n" +
			"empty::3:3:nopw:foo:/bin/zsh\n" +
			"weak:$1$asdf:4:4:note:/home/weak:/usr/sbin/nologin\n"),
		Metadata: &pb.FileMetadata{Permissions: 0777},
	}

	if findings, err := AnalyzePasswd(manyFindingsTest); err != nil {
		t.Errorf("AnalyzePasswd(%v): unexpected error %v", manyFindingsTest, err)
	} else if len(findings) != 4 {
		t.Errorf("AnalyzePasswd(%v): got %v findings, want 4", manyFindingsTest, len(findings))
	}
}

// TestShadowAnalyzing checks if the AnalyzeShadow method is returning
// correct number of findings or errors.
func TestShadowAnalyzing(t *testing.T) {
	malformedTest := &pb.File{Data: []byte("::::::")}

	if _, err := AnalyzeShadow(malformedTest); err == nil {
		t.Errorf("AnalyzeShadow(%v): expected error, got nil", malformedTest)
	}

	manyFindingsTest := &pb.File{
		Data: []byte("root:!$1$salt$hash:16600:0:99999:7:::\n" +
			"empty::12345:0:99999:7:::\n" +
			"weak:$1$salt$hash:15999:0:99999:7:::\n"),
		Metadata: &pb.FileMetadata{Permissions: 0777},
	}

	if findings, err := AnalyzeShadow(manyFindingsTest); err != nil {
		t.Errorf("AnalyzeShadow(%v): unexpected error %v", manyFindingsTest, err)
	} else if len(findings) != 3 {
		t.Errorf("AnalyzeShadow(%v): got %v findings, want 3", manyFindingsTest, len(findings))
	}
}

func TestPasswdPermissions(t *testing.T) {
	metadata := &pb.FileMetadata{
		Permissions: 0777,
	}

	if passwdSecure := ArePasswdPermissionsSecure(metadata); passwdSecure {
		t.Errorf("ArePasswdPermissionsSecure(%v) = %v, want %v",
			os.FileMode(metadata.Permissions), passwdSecure, !passwdSecure)
	}

	metadata.Permissions = 0644
	if passwdSecure := ArePasswdPermissionsSecure(metadata); !passwdSecure {
		t.Errorf("ArePasswdPermissionsSecure(%v) = %v, want %v",
			os.FileMode(metadata.Permissions), passwdSecure, !passwdSecure)
	}
}

func TestShadowPermissions(t *testing.T) {
	metadata := &pb.FileMetadata{
		Permissions: 0777,
	}

	if shadowSecure := AreShadowPermissionsSecure(metadata); shadowSecure {
		t.Errorf("AreShadowPermissionsSecure(%v) = %v, want %v",
			os.FileMode(metadata.Permissions), shadowSecure, !shadowSecure)
	}

	metadata.Permissions = 0640
	if shadowSecure := AreShadowPermissionsSecure(metadata); !shadowSecure {
		t.Errorf("AreShadowPermissionsSecure(%v) = %v, want %v",
			os.FileMode(metadata.Permissions), shadowSecure, !shadowSecure)
	}
}

func TestShadowParsing(t *testing.T) {
	malformedShadowTests := []string{
		"::::",
		"::str::::::",
		":::str:::::",
		"::::str::::",
		":::::str:::",
		"::::::str::",
		":::::::str:",
	}

	for _, line := range malformedShadowTests {
		if _, err := NewShadowInfo(line); err == nil {
			t.Errorf("NewShadowInfo should fail for %q", line)
		}
	}

	goodShadowLine := "user:pass:1000:0:1000:7:7::"
	expectedTime := time.Date(1970, 0, 0, 0, 0, 0, 0, time.UTC).AddDate(0, 0, 1000)
	expectedShadow := ShadowInfo{"user", "pass", expectedTime, 0, 1000, 7, 7, time.Time{}, nil}

	shadow, err := NewShadowInfo(goodShadowLine)

	if err != nil {
		t.Errorf("NewShadowInfo(%q) shouldn't return an error %v", goodShadowLine, err)
	} else if !reflect.DeepEqual(shadow, expectedShadow) {
		t.Errorf("NewShadowInfo(%q) = %v, want %v", goodShadowLine, shadow, expectedShadow)
	}
}

func TestPasswdParsing(t *testing.T) {
	malformedPasswdLines := []string{
		":::",
		"root:x:baduid:0:root:/root:/bin/bash",
		"root:x:0:badgid:root:/root:/bin/bash",
		"root:x:0::root;/root:",
	}

	for _, line := range malformedPasswdLines {
		if _, err := NewUser(line); err == nil {
			t.Errorf("NewUser should fail for %q", line)
		}
	}

	correctUserLine := "root:x:0:0:root:/root:/bin/bash"
	expectedUser := User{"root", "x", 0, 0, "root", "/root", "/bin/bash"}

	user, err := NewUser(correctUserLine)

	if err != nil {
		t.Errorf("NewUser(%q) shouldn't return an error %v", correctUserLine, err)
	} else if user != expectedUser {
		t.Errorf("NewUser(%q) = %v, want %v", correctUserLine, user, expectedUser)
	}
}

func TestBackdooredRoot(t *testing.T) {
	var backdooredRootTests = []struct {
		u    User
		want bool
	}{
		{User{Username: "notroot", UID: 0}, true},
		{User{Username: "root", UID: 0}, false},
		{User{Username: "user", UID: 1234}, false},
	}

	for _, test := range backdooredRootTests {
		if have := test.u.IsBackdooredRoot(); have != test.want {
			t.Errorf("IsBackdooredRoot() for %v, have %t, want %t", test.u, have, test.want)
		}
	}
}

func TestWeakHashes(t *testing.T) {
	var weakHashesTests = []struct {
		hash PasswordHash
		want bool
	}{
		{"", false},
		{"$1$salt$hash", true},
		{"$2a$salt$hash", false},
		{"DESmaybe", true},
		{"$5$salt$hash", false},
		{"$6$salt$hash", false},
	}

	for _, test := range weakHashesTests {
		if have := test.hash.UsesWeakHashing(); have != test.want {
			t.Errorf("UsesWeakCrypto() for %v, have %t, want %t", test.hash, have, test.want)
		}
	}
}
