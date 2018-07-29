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
	"log"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"

	"github.com/google/minions/go/overlord/interests"
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

	log.Println("Reaching out to all minions.")
	// Build map of minions.
	for _, addr := range minionAddresses {
		log.Printf("Contacting %s\n", addr)
		c, err := grpc.Dial(addr, opts...)
		if err != nil {
			return nil, err
		}
		log.Println("Ok, minion connected")
		server.minions[addr] = mpb.NewMinionClient(c)
	}

	log.Println("Retrieving initial interests")
	for _, m := range server.minions {
		// TODO(paradoxengine): most likely, a deadline here?
		intResp, err := m.ListInitialInterests(ctx, &mpb.ListInitialInterestsRequest{})
		if err != nil {
			return nil, err
		}
		for _, i := range intResp.GetInterests() {
			log.Printf("Got interest: %s", i)
			server.initialInterests = append(server.initialInterests, i)
		}
	}
	log.Printf("Minimizing interests, now %d", len(server.initialInterests))
	server.initialInterests = interests.Minify(server.initialInterests)
	log.Printf("Minimized interests, now %d", len(server.initialInterests))
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
	// IMPORTANT NOTE: This is a broken implementation that always returns the initial list.
	return &pb.ListInterestsResponse{Interests: s.initialInterests, NextPageToken: ""}, nil
}

// ScanFiles runs security scan on a set of files, assuming they were actually
// needed by the backend minions.
func (s *Server) ScanFiles(ctx context.Context, req *pb.ScanFilesRequest) (*pb.ScanFilesResponse, error) {
	// IMPORTANT NOTE: this is a broken implementation where we assume all data
	// always fits in the first data chunk. This is really only built for testing.
	var files []*mpb.File
	for _, f := range req.GetFiles() {
		f.GetDataChunks()
		files = append(files, &mpb.File{
			Metadata: f.GetMetadata(),
			Data:     f.GetDataChunks()[0].GetData(),
		})
	}

	var newInterests []*mpb.Interest
	var results []*mpb.Finding
	for _, m := range s.minions {
		c, _ := context.WithTimeout(ctx, 60*time.Second)
		r := &mpb.AnalyzeFilesRequest{
			ScanId: req.GetScanId(),
			Files:  files,
		}
		minionResponse, err := m.AnalyzeFiles(c, r)
		if err != nil {
			return nil, err
		}
		newInterests = append(newInterests, minionResponse.GetNewInterests()...)
		results = append(results, minionResponse.GetFindings()...)
	}
	return &pb.ScanFilesResponse{NewInterests: newInterests, Results: results}, nil
}
