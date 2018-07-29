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
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"syscall"

	minions "github.com/google/minions/proto/minions"
	pb "github.com/google/minions/proto/overlord"
)

// loadFiles builds the File protos for a given interest in chunks,
// topping at maximum size and files count. Note we do not support
// content regexps at this point.
func loadFiles(i *minions.Interest, maxKb int, maxFiles int, root string) ([][]*pb.File, error) {
	var paths []string
	// Note we assume a unix filesystem here. Might want to revisit.
	filepath.Walk(root, func(path string, f os.FileInfo, _ error) error {
		// For the naive implementation, let's check every file, but really
		// here we need to bail out early instead and return filepath.SkipDir
		// anytime we take a wrong turn.
		if !f.IsDir() {
			// Let's see if we match!
			r, err := regexp.MatchString(i.GetPathRegexp(), path)
			if err == nil && r {
				paths = append(paths, path)
			}
		}
		return nil
	})

	var files [][]*pb.File
	var fs []*pb.File
	for _, p := range paths {
		metadata, err := getMetadata(p)
		if err != nil {
			return nil, err
		}
		f := &pb.File{Metadata: metadata, DataChunks: nil}
		switch dataType := i.GetDataType(); dataType {
		case minions.Interest_METADATA:
			break
		case minions.Interest_METADATA_AND_DATA:
			chunks, err := getDataChunks(p)
			if err != nil {
				return nil, err
			}
			f.DataChunks = chunks
			break
		default:
			return nil, errors.New("Unknown interest type")
		}
		fs = append(fs, f)
	}
	files = append(files, fs)

	return files, nil
}

// getMetadata is heavily linux skewed, but so is minions right now.
// It's fairly easy to port to windows by adding the appropriate data
// structure, but not planned for now.
func getMetadata(path string) (*minions.FileMetadata, error) {
	s, err := os.Stat(path)
	if err != nil {
		// I suspect this is too aggressive, as this can fail for a number
		// of reasons, including permissions. It might be wiser to log
		// and proceed, but let's try as is now.
		return nil, err
	}
	sys := s.Sys()
	if sys == nil {
		return nil, errors.New("cannot access OS-specific metadata")
	}

	m := &minions.FileMetadata{Path: path}
	// TODO(paradoxengine): these conversions are all over the place :-(
	m.OwnerUid = int32(sys.(*syscall.Stat_t).Uid)
	m.OwnerGid = int32(sys.(*syscall.Stat_t).Gid)
	m.Permissions = uint32(s.Mode())
	m.Size = s.Size()
	return m, nil
}

// getDataChunks splits the file at the path in a set of chunks.
func getDataChunks(path string) ([]*pb.DataChunk, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var chunks []*pb.DataChunk
	// Arbitrary size of each data chunk.
	var chunkSize = 1024 * 1024 * 2
	dataLen := len(data)
	for i := 0; i < dataLen; i += chunkSize {
		var chunk []byte
		if i+chunkSize >= dataLen {
			chunk = data[i:]
		} else {
			chunk = data[i : i+chunkSize]
		}
		chunks = append(chunks, &pb.DataChunk{
			Offset: int64(i),
			Data:   chunk,
		})
	}
	return chunks, nil
}