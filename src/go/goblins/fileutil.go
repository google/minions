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

// Package goblins contains common code across Goblins
package goblins

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/google/minions/go/overlord/interests"
	mpb "github.com/google/minions/proto/minions"
	pb "github.com/google/minions/proto/overlord"
)

// loadFiles builds the File protos for a slice of interests in chunks,
// topping at maximum size and files count. Note we do not support
// content regexps at this point (i.e. we do not check file contents).
// Note that the root path gets automatically removed from the file's path.
func loadFiles(intrs []*mpb.Interest, maxKb int, maxFiles int, root string) ([][]*pb.File, error) {
	// Defensively minify the interests: this should have already happened but better safe than sorry.
	intrs = interests.Minify(intrs)

	paths := make(map[string]mpb.Interest_DataType)
	// Note we assume a unix filesystem here. Might want to revisit.
	err := filepath.Walk(root, func(path string, f os.FileInfo, e error) error {

		if e != nil {
			// If we don't have permission, skip the directory but don't bail out.
			if os.IsPermission(e) {
				return filepath.SkipDir
			}
			// This seems to happen for volatile dirs.
			if os.IsNotExist(e) {
				return filepath.SkipDir
			}

			log.Printf("prevent panic by handling failure accessing a path %q: %v\n", path, e)
			return e
		}
		// For the naive implementation, let's check every file, but really
		// here we need to bail out early instead and return filepath.SkipDir
		// anytime we take a wrong turn.
		if !f.IsDir() {
			// Let's see if we match any interest!
			for _, i := range intrs {
				// Note we have to remove the root directory.
				r, err := regexp.MatchString(i.GetPathRegexp(), removeRoot(path, root))
				if err == nil && r {
					log.Printf("Great, %s matched %s\n", path, i.GetPathRegexp())
					// NOTE: this overwrites existing datatypes, under the assumption that the
					// minification has taken care of this.
					paths[path] = i.GetDataType()
				}
			}
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("Failed Walk: %v", err)
	}

	var files [][]*pb.File
	var fs []*pb.File
	// TODO(paradoxengine): implement limits on count of files and size.
	for path, dataType := range paths {
		metadata, err := getMetadata(path, root)
		if err != nil {
			// Metadata building can fail for a lot of reasons, so we don't
			// just kill it, but rather continue.
			log.Printf("Cannot create Metadata for %s. %v", path, err)
			continue
		}
		f := &pb.File{Metadata: metadata, DataChunks: nil}
		switch dataType {
		case mpb.Interest_METADATA:
			break
		case mpb.Interest_METADATA_AND_DATA:
			chunks, err := getDataChunks(path)
			if err != nil {
				if os.IsPermission(err) {
					log.Printf("Cannot send %s. Permission denied. Skipping.", path)
					continue
				} else {
					return nil, err
				}
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
func getMetadata(path string, rootDir string) (*mpb.FileMetadata, error) {
	s, err := os.Stat(path)
	if err != nil {
		// This can fail for a number of reasons, including
		// permissions and broken sylinks.
		return nil, err
	}
	sys := s.Sys()
	if sys == nil {
		return nil, errors.New("cannot access OS-specific metadata")
	}

	// Note how we remove the root path to let the minions handle it.
	m := &mpb.FileMetadata{Path: removeRoot(path, rootDir)}
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

func removeRoot(path string, root string) string {
	return filepath.Clean(strings.Replace(path, root, "/", 1))
}

// SendFiles iteratively sends files drawing them from the rootpath,
// using the provided Overlord client.
func SendFiles(client pb.OverlordClient, scanID string, interests []*mpb.Interest, rootPath string) ([]*mpb.Finding, error) {
	var results []*mpb.Finding
	// TODO: handle max files and bytes per request limits
	files, err := loadFiles(interests, 0, 0, rootPath)
	if err != nil {
		return nil, err
	}

	for _, fs := range files {
		for _, ff := range fs {
			log.Printf("Sending file %s", ff.GetMetadata().GetPath())
		}
		sfr := &pb.ScanFilesRequest{ScanId: scanID, Files: fs}
		ctx, _ := context.WithTimeout(context.Background(), 60*time.Second)
		resp, err := client.ScanFiles(ctx, sfr)
		log.Printf("Files sent. Response: %v", resp)
		if err != nil {
			return nil, err
		}
		// Iterate on new interests
		if len(resp.GetNewInterests()) > 0 {
			log.Printf("Got new interests!")
			r, err := SendFiles(client, scanID, resp.GetNewInterests(), rootPath)
			if err != nil {
				return nil, err
			}
			results = append(results, r...)
		}
		results = append(results, resp.GetResults()...)
	}
	return results, nil
}
