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

package overlord

import (
	"errors"
	"fmt"
	"sort"
	"time"

	mpb "github.com/google/minions/proto/minions"
	pb "github.com/google/minions/proto/overlord"
	"github.com/patrickmn/go-cache"
)

// StateManager handles the state of an Overlord through multiple
// scans.
type StateManager interface {
	// AddFiles atomically sets the state of a minion during a scan.
	AddFiles(scanID string, files []*pb.File) error
	// AddInterest adds a new interest for a given minion to the state of the scan.
	AddInterest(scanID string, interest *mpb.Interest, minion string) error
	// CreateScan initializes the state for a scan.
	CreateScan(scanID string) error
	// GetFiles returns all the files known for a given ScanID
	GetFiles(scanID string) ([]*pb.File, error)
	// GetInterests returns all the interests known for a given ScanID, mapped to minions
	GetInterests(scanID string) ([]*mappedInterest, error)
	// RemoveFile atomically removes a given file from the state.
	RemoveFile(scanID string, file *pb.File) error
	// ScanExists returns true if any state at all is known about the scan.
	ScanExists(scanID string) bool
}

// LocalStateManager handles state through a local time-expiring cache.
type LocalStateManager struct {
	lc *cache.Cache
}

// state stores the current state of a scan
type state struct {
	interests []*mappedInterest
	files     map[string]*pb.File
}

// NewLocalStateManager creates a StateManager backed by a local cache.
func NewLocalStateManager() *LocalStateManager {
	lc := cache.New(5*time.Minute, 10*time.Minute)
	return &LocalStateManager{lc: lc}
}

// AddFiles adds a set of files to the state. This will also dynamically
// merge chunks of files.
func (l *LocalStateManager) AddFiles(scanID string, files []*pb.File) error {
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
func (l *LocalStateManager) CreateScan(scanID string) error {
	l.setState(scanID, state{
		interests: make([]*mappedInterest, 0),
		files:     make(map[string]*pb.File),
	})
	return nil
}

// RemoveFile removes a given file from the state for a scan, if present.
func (l *LocalStateManager) RemoveFile(scanID string, file *pb.File) error {
	//l.lc.Delete(l.fileKey(scanID, file))
	// TODO: implement me
	return nil
}

// AddInterest adds a new interest for a given minion to the state of the scan.
func (l *LocalStateManager) AddInterest(scanID string, interest *mpb.Interest, minion string) error {
	s, _ := l.getState(scanID)
	s.interests = append(s.interests, &mappedInterest{
		interest: interest,
		minion:   minion,
	})
	l.setState(scanID, s)
	return nil
}

// ScanExists returns true if any state at all is known about the scan.
func (l *LocalStateManager) ScanExists(scanID string) bool {
	_, exists := l.lc.Get(scanID)
	return exists
}

// GetFiles returns all the files known for a given ScanID
func (l *LocalStateManager) GetFiles(scanID string) ([]*pb.File, error) {
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
func (l *LocalStateManager) GetInterests(scanID string) ([]*mappedInterest, error) {
	s, found := l.getState(scanID)
	if !found {
		return nil, errors.New("Scan does not exist")
	}
	return s.interests, nil
}

func (l *LocalStateManager) getState(scanID string) (state, bool) {
	s, found := l.lc.Get(scanID)
	return s.(state), found
}

func (l *LocalStateManager) setState(scanID string, s state) {
	l.lc.SetDefault(scanID, s)
}
