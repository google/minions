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

package main

import (
	"io/ioutil"
	"os"
	"testing"

	minions "github.com/google/minions/proto/minions"
	"github.com/stretchr/testify/assert"
)

func TestParsesFiles_onFilesPresent_selectsFiles(t *testing.T) {
	dir, err := createFile(t, "common_goblins_test", "/foo/bar", "temp.tmp", os.ModePerm)
	assert.NoError(t, err)
	defer os.RemoveAll(dir)

	i := &minions.Interest{DataType: minions.Interest_METADATA, PathRegexp: ".*\\.tmp"}
	files, err := loadFiles(i, 10000, 1000, dir)
	assert.NoError(t, err)
	p := files[0][0].GetMetadata().GetPath()
	assert.Equal(t, dir+"/foo/bar/temp.tmp", p)
}

func TestParsesFiles_onFilesPresent_getsMetadata(t *testing.T) {
	dir, err := createFile(t, "common_goblins_test", "/foo", "temp.tmp", 0700)
	assert.NoError(t, err)
	defer os.RemoveAll(dir)

	i := &minions.Interest{DataType: minions.Interest_METADATA, PathRegexp: ".*\\.tmp"}
	files, err := loadFiles(i, 10000, 1000, dir)
	assert.NoError(t, err)
	p := files[0][0].GetMetadata().GetPermissions()

	assert.Equal(t, uint32(0700), p)
}

func TestParsesFiles_onFilesPresent_readsContents(t *testing.T) {
	dir, err := createFile(t, "common_goblins_test", "", "data.tmp", 0700)
	b := []byte{115, 111, 109, 101, 10}
	f, err := os.Create(dir + "/data.tmp")
	_, err = f.Write(b)
	assert.NoError(t, err)
	f.Close()
	defer os.RemoveAll(dir)

	i := &minions.Interest{DataType: minions.Interest_METADATA_AND_DATA, PathRegexp: ".*\\.tmp"}
	files, err := loadFiles(i, 10000, 1000, dir)
	assert.NoError(t, err)
	chunks := files[0][0].GetDataChunks()
	data := chunks[0].GetData()
	assert.Equal(t, b, data)
}

func TestParsesFiles_onFilesMissing_doesNotSelectFiles(t *testing.T) {
	dir, err := createFile(t, "common_goblins_test", "/", "temp.val1", os.ModePerm)
	assert.NoError(t, err)
	defer os.RemoveAll(dir)

	i := &minions.Interest{DataType: minions.Interest_METADATA, PathRegexp: ".*\\.val2"}
	files, err := loadFiles(i, 10000, 1000, dir)
	assert.NoError(t, err)
	// Sadly empty does not really support 2 dimensional slices.
	assert.Empty(t, files[0])
}

func createFile(t *testing.T, base string, subdirs string, name string, perm os.FileMode) (string, error) {
	dir, err := ioutil.TempDir("", base)
	err = os.MkdirAll(dir+subdirs, perm)
	assert.NoError(t, err)
	fname := dir + subdirs + "/" + name
	_, err = os.Create(fname)
	assert.NoError(t, err)
	err = os.Chmod(fname, perm)
	assert.NoError(t, err)
	return dir, err
}
