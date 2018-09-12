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

package goblins

import (
	"io/ioutil"
	"os"
	"testing"

	minions "github.com/google/minions/proto/minions"
	"github.com/stretchr/testify/require"
)

func TestParsesFiles_onFilesPresent_selectsFiles(t *testing.T) {
	dir, err := createFile(t, "common_goblins_test", "/foo/bar", "temp.tmp", os.ModePerm)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	i := &minions.Interest{DataType: minions.Interest_METADATA, PathRegexp: ".*\\.tmp"}
	files, err := LoadFiles([]*minions.Interest{i}, 10000, 1000, dir)
	require.NoError(t, err)
	p := files[0][0].GetMetadata().GetPath()
	require.Equal(t, dir+"/foo/bar/temp.tmp", p)
}

func TestParsesFiles_onSelectedFileUnaccessible_doesNotCrash(t *testing.T) {
	// We are owners of the file, but taking away our rights.
	dir, err := createFile(t, "common_goblins_test", "/foo/bar", "temp.tmp", os.ModePerm)
	require.NoError(t, err)
	err = os.Chmod(dir+"/foo/bar/temp.tmp", 00000)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	i := &minions.Interest{DataType: minions.Interest_METADATA_AND_DATA, PathRegexp: ".*\\.tmp"}
	files, err := LoadFiles([]*minions.Interest{i}, 10000, 1000, dir)
	require.NoError(t, err)
	// Expect that will will skip, with no errors.
	require.Empty(t, files[0])
}

func TestParsesFiles_onMultipleInterests_selectsFiles(t *testing.T) {
	dir, err := createFile(t, "common_goblins_test", "/foo/bar", "temp.tmp", os.ModePerm)
	require.NoError(t, err)
	defer os.RemoveAll(dir)
	fname := dir + "/foo/bar/temp.foo"
	_, err = os.Create(fname)
	require.NoError(t, err)
	err = os.Chmod(fname, os.ModePerm)
	require.NoError(t, err)

	i := &minions.Interest{DataType: minions.Interest_METADATA, PathRegexp: ".*\\.tmp"}
	i2 := &minions.Interest{DataType: minions.Interest_METADATA, PathRegexp: ".*\\.foo"}

	files, err := LoadFiles([]*minions.Interest{i, i2}, 10000, 1000, dir)
	require.NoError(t, err)

	expectedFiles := []string{dir + "/foo/bar/temp.foo", dir + "/foo/bar/temp.tmp"}
	require.Contains(t, expectedFiles, files[0][0].GetMetadata().GetPath())
	require.Contains(t, expectedFiles, files[0][1].GetMetadata().GetPath())
}

func TestParsesFiles_onFilesPresent_getsMetadata(t *testing.T) {
	dir, err := createFile(t, "common_goblins_test", "/foo", "temp.tmp", 0700)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	i := &minions.Interest{DataType: minions.Interest_METADATA, PathRegexp: ".*\\.tmp"}
	files, err := LoadFiles([]*minions.Interest{i}, 10000, 1000, dir)
	require.NoError(t, err)
	p := files[0][0].GetMetadata().GetPermissions()

	require.Equal(t, uint32(0700), p)
}

func TestParsesFiles_onFilesPresent_readsContents(t *testing.T) {
	dir, err := createFile(t, "common_goblins_test", "", "data.tmp", 0700)
	b := []byte{115, 111, 109, 101, 10}
	f, err := os.Create(dir + "/data.tmp")
	_, err = f.Write(b)
	require.NoError(t, err)
	f.Close()
	defer os.RemoveAll(dir)

	i := &minions.Interest{DataType: minions.Interest_METADATA_AND_DATA, PathRegexp: ".*\\.tmp"}
	files, err := LoadFiles([]*minions.Interest{i}, 10000, 1000, dir)
	require.NoError(t, err)
	chunks := files[0][0].GetDataChunks()
	data := chunks[0].GetData()
	require.Equal(t, b, data)
}

func TestParsesFiles_onFilesMissing_doesNotSelectFiles(t *testing.T) {
	dir, err := createFile(t, "common_goblins_test", "/", "temp.val1", os.ModePerm)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	i := &minions.Interest{DataType: minions.Interest_METADATA, PathRegexp: ".*\\.val2"}
	files, err := LoadFiles([]*minions.Interest{i}, 10000, 1000, dir)
	require.NoError(t, err)
	// Sadly empty does not really support 2 dimensional slices.
	require.Empty(t, files[0])
}

func createFile(t *testing.T, base string, subdirs string, name string, perm os.FileMode) (string, error) {
	dir, err := ioutil.TempDir("", base)
	err = os.MkdirAll(dir+subdirs, perm)
	require.NoError(t, err)
	fname := dir + subdirs + "/" + name
	_, err = os.Create(fname)
	require.NoError(t, err)
	err = os.Chmod(fname, perm)
	require.NoError(t, err)
	return dir, err
}
