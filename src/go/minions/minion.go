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

/*
Package minions specifies a common Minion interface.

A minion performs certain checks on the files provided and returns issues
it finds to the caller. Each minion is interested in certain files that can
be discovered using ListInitialInterests method. A minion can also return
additional interests to the caller as a result of an AnalyzeFiles method call.
*/
package minions

import (
	"fmt"
	"time"

	pb "github.com/google/minions/proto/minions"
	"github.com/patrickmn/go-cache"
	"golang.org/x/net/context"
)

// Minion is a interface that should be implemented by every Minion.
type Minion interface {
	// ListInitialInterests returns the initial Interests of a Minion.
	ListInitialInterests(ctx context.Context, req *pb.ListInitialInterestsRequest) (*pb.ListInitialInterestsResponse, error)
	// AnalyzeFiles returns security issues found in files from AnalyzeFilesRequest.
	AnalyzeFiles(ctx context.Context, req *pb.AnalyzeFilesRequest) (*pb.AnalyzeFilesResponse, error)
}

// StateManager handles state keeping for a minion, allowing it to save
// whatever needs saving. It might or might not work across horizontally
// scaled minions of the same type: check implementors.
type StateManager interface {
	// Set atomically sets the state of a minion during a scan.
	Set(scanID string, state interface{}) error
	// Get atomically retrieves the state of a minion during a scan.
	// Returns an error if the key was not found.
	Get(scanID string) (interface{}, error)
	// Has returns true if there is any set state for the given scan.
	Has(scanID string) bool
}

// LocalStateManager uses a local cache to manage a minion's state.
type LocalStateManager struct {
	lc *cache.Cache
}

// NewLocalStateManager creates a StateManager backed by a local cache.
func NewLocalStateManager() *LocalStateManager {
	lc := cache.New(5*time.Minute, 10*time.Minute)
	return &LocalStateManager{lc: lc}
}

// Set atomically sets the state of a minion during a scan.
func (l *LocalStateManager) Set(scanID string, state interface{}) error {
	l.lc.SetDefault(scanID, state)
	return nil
}

// Get atomically retrieves the state of a minion during a scan.
func (l *LocalStateManager) Get(scanID string) (interface{}, error) {
	v, found := l.lc.Get(scanID)
	if !found {
		return nil, fmt.Errorf("Cannot find state for scan: %s", scanID)
	}
	return v, nil
}

// Has returns true if there is any set state for the given scan.
func (l *LocalStateManager) Has(scanID string) bool {
	_, found := l.lc.Get(scanID)
	return found
}
