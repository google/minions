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

// Package state handles, unsurprisingly, state for the Overlord.
package state

import (
	"errors"
	"fmt"
	"sort"
	"time"

	mpb "github.com/google/minions/proto/minions"
	pb "github.com/google/minions/proto/overlord"
	"github.com/patrickmn/go-cache"
)

// Local handles state through a local time-expiring cache.
type Local struct {
	lc *cache.Cache
}

// MappedInterest stores the interest along with the address of the minion which expressed it.
type MappedInterest struct {
	Interest *mpb.Interest
	Minion   string
}

// state stores the current state of a scan
type state struct {
	interests []*MappedInterest
	files     map[string]*pb.File
}

// NewLocal creates a StateManager backed by a local cache.
func NewLocal() *Local {
	lc := cache.New(5*time.Minute, 10*time.Minute)
	return &Local{lc: lc}
}

// AddFiles adds a set of files to the state. This will also dynamically
// merge chunks of files.
func (l *Local) AddFiles(scanID string, files []*pb.File) error {
	s, found := l.getState(scanID)
	if !found {
		return errors.New("Cannot find state of scan")
	}
	for _, f := range files {
		currentFile, alreadyKnown := s.files[f.GetMetadata().GetPath()]
		if !alreadyKnown {
			currentFile = &pb.File{
				Metadata: f.GetMetadata(),
				DataChunks: []*pb.DataChunk{
					&pb.DataChunk{
						Offset: 0,
					},
				},
			}
			s.files[f.GetMetadata().GetPath()] = currentFile
		}
		currentChunk := currentFile.GetDataChunks()[0]
		size := int64(len(currentChunk.GetData()))

		newChunks := f.GetDataChunks()
		sort.Slice(newChunks, func(i, j int) bool {
			return newChunks[i].GetOffset() < newChunks[j].GetOffset()
		})
		for _, chunk := range newChunks {
			if chunk.GetOffset() < size {
				return fmt.Errorf("received a file with overlapping DataChunks")
			}
			if chunk.GetOffset() != size {
				return fmt.Errorf("received a file with missing DataChunks")
			}
			currentChunk.Data = append(currentChunk.Data, chunk.GetData()...)
			size += int64(len(chunk.GetData()))
		}
	}
	l.setState(scanID, s)
	return nil
}

// CreateScan initializes the state for a scan. It resets the state
// if it already exists.
func (l *Local) CreateScan(scanID string) error {
	l.setState(scanID, state{
		interests: make([]*MappedInterest, 0),
		files:     make(map[string]*pb.File),
	})
	return nil
}

// RemoveFile removes a given file from the state for a scan, if present.
// Returns true if the file has been removed, false otherwise
// (i.e. the file was not in the state)
func (l *Local) RemoveFile(scanID string, file *pb.File) (bool, error) {
	s, ok := l.getState(scanID)
	if !ok {
		return false, fmt.Errorf("No state for scan %s", scanID)
	}
	path := file.GetMetadata().GetPath()
	if _, ok := s.files[path]; ok {
		delete(s.files, path)
		l.setState(scanID, s)
		return true, nil
	}
	return false, nil
}

// AddInterest adds a new interest for a given minion to the state of the scan.
func (l *Local) AddInterest(scanID string, interest *mpb.Interest, minion string) error {
	s, _ := l.getState(scanID)
	s.interests = append(s.interests, &MappedInterest{
		Interest: interest,
		Minion:   minion,
	})
	l.setState(scanID, s)
	return nil
}

// ScanExists returns true if any state at all is known about the scan.
func (l *Local) ScanExists(scanID string) bool {
	_, exists := l.lc.Get(scanID)
	return exists
}

// GetFiles returns all the files known for a given ScanID
func (l *Local) GetFiles(scanID string) ([]*pb.File, error) {
	s, found := l.getState(scanID)
	if !found {
		return nil, errors.New("Scan does not exist")
	}
	files := make([]*pb.File, 0)
	for _, f := range s.files {
		files = append(files, f)
	}
	return files, nil
}

// GetInterests returns all the interests known for a given ScanID, mapped to minions
func (l *Local) GetInterests(scanID string) ([]*MappedInterest, error) {
	s, found := l.getState(scanID)
	if !found {
		return nil, errors.New("Scan does not exist")
	}
	return s.interests, nil
}

func (l *Local) getState(scanID string) (state, bool) {
	s, found := l.lc.Get(scanID)
	return s.(state), found
}

func (l *Local) setState(scanID string, s state) {
	l.lc.SetDefault(scanID, s)
}
