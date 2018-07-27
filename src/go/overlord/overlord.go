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
	"google.golang.org/grpc"

	mpb "github.com/google/minions/proto/minions"
	pb "github.com/google/minions/proto/overlord"
	"golang.org/x/net/context"
)

// Server implements the OverlordServer interface, the orchestrator of Minions' infrastructure.
type Server struct {
	minions          map[string]mpb.MinionClient // THe minions we know about and their address
	initialInterests []*mpb.Interest
}

// New returns an initialized Server, which connects to a set of pre-specified minions
// to initialize them.
func New(ctx context.Context, minionAddresses []string, opts ...grpc.DialOption) (*Server, error) {
	server := &Server{
		minions:          make(map[string]mpb.MinionClient),
		initialInterests: nil,
	}

	// Build map of minions.
	for _, addr := range minionAddresses {
		c, err := grpc.Dial(addr, opts...)
		if err != nil {
			return nil, err
		}
		server.minions[addr] = mpb.NewMinionClient(c)
	}

	// Init initial interests by querying each minion.
	for _, m := range server.minions {
		// TODO(paradoxengine): most likely, a deadline here?
		intResp, err := m.ListInitialInterests(ctx, &mpb.ListInitialInterestsRequest{})
		if err != nil {
			return nil, err
		}
		for _, i := range intResp.GetInterests() {
			server.initialInterests = append(server.initialInterests, i)
		}
	}

	return server, nil
}

// CreateScan set up a security scan which can then be fed files via ScanFiles.
// It returns a UUID identifying the scan from now on and the list of initial
// Interests.
func (s *Server) CreateScan(ctx context.Context, req *pb.CreateScanRequest) (*pb.Scan, error) {
	// Scans are tracked by UUID, so let's start by generating it.
	scan := &pb.Scan{}
	u, _ := uuid.NewRandom()
	scan.ScanId = u.String()
	scan.Interests = s.initialInterests
	// TODO(claudioc): this is where we'd create the state of the scan the first time.
	return scan, nil
}

// ListInterests returns the interests for a given scan, i.e. the files or metadata
// that have to be fed the Overlord for security scanning.
func (s *Server) ListInterests(ctx context.Context, req *pb.ListInterestsRequest) (*pb.ListInterestsResponse, error) {
	return &pb.ListInterestsResponse{Interests: nil, NextPageToken: "token"}, nil
}

// ScanFiles runs security scan on a set of files, assuming they were actually
// needed by the backend minions.
func (s *Server) ScanFiles(ctx context.Context, req *pb.ScanFilesRequest) (*pb.ScanFilesResponse, error) {
	return &pb.ScanFilesResponse{NewInterests: nil, Results: nil}, nil
}
