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
	"github.com/google/uuid"

	pb "github.com/google/minions/proto/overlord"
	"golang.org/x/net/context"
)

// Overlord is the orchestrator of Minions' infrastructure.
type Overlord struct {
}

// CreateScan set up a security scan which can then be fed files via ScanFiles.
// It returns a UUID identifying the scan from now on and the list of initial
// Interests.
func (s *Overlord) CreateScan(ctx context.Context, req *pb.CreateScanRequest) (*pb.Scan, error) {
	// Scans are tracked by UUID, so let's start by generating it.
	scan := &pb.Scan{}
	u, _ := uuid.NewRandom()
	scan.ScanId = u.String()

	// TODO(claudio): fetch interests from all registered minions and add them here.

	return scan, nil
}

// ListInterests returns the interests for a given scan, i.e. the files or metadata
// that have to be fed the Overlord for security scanning.
func (s *Overlord) ListInterests(ctx context.Context, req *pb.ListInterestsRequest) (*pb.ListInterestsResponse, error) {
	return &pb.ListInterestsResponse{Interests: nil, NextPageToken: "token"}, nil
}

// ScanFiles runs security scan on a set of files, assuming they were actually
// needed by the backend minions.
func (s *Overlord) ScanFiles(ctx context.Context, req *pb.ScanFilesRequest) (*pb.ScanFilesResponse, error) {
	return &pb.ScanFilesResponse{NewInterests: nil, Results: nil}, nil
}
