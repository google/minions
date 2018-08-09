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

	"fmt"

	"github.com/google/minions/go/overlord/interests"
	"github.com/google/uuid"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	mpb "github.com/google/minions/proto/minions"
	pb "github.com/google/minions/proto/overlord"
)

// Server implements the OverlordServer interface, the orchestrator of Minions' infrastructure.
type Server struct {
	minions          map[string]mpb.MinionClient // THe minions we know about and their address
	initialInterests []*mappedInterest
	scans            map[string]state
}

// mappedInterest stores the interest along with the address of the minion which expressed it.
type mappedInterest struct {
	interest *mpb.Interest
	minion   string
}

// state stores the current state of the scan
type state struct {
	interests []*mappedInterest
}

// New returns an initialized Server, which connects to a set of pre-specified minions
// to initialize them.
func New(ctx context.Context, minionAddresses []string, opts ...grpc.DialOption) (*Server, error) {
	server := &Server{
		minions: make(map[string]mpb.MinionClient),
		scans:   make(map[string]state),
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
	for name, m := range server.minions {
		// TODO(paradoxengine): most likely, a deadline here?
		intResp, err := m.ListInitialInterests(ctx, &mpb.ListInitialInterestsRequest{})
		if err != nil {
			return nil, err
		}
		for _, v := range intResp.GetInterests() {
			server.initialInterests = append(server.initialInterests, &mappedInterest{
				interest: v,
				minion:   name,
			})
		}
	}

	log.Printf("Initial interests: %d", len(server.initialInterests))
	return server, nil
}

// CreateScan set up a security scan which can then be fed files via ScanFiles.
// It returns a UUID identifying the scan from now on and the list of initial
// Interests.
func (s *Server) CreateScan(ctx context.Context, req *pb.CreateScanRequest) (*pb.Scan, error) {
	// Scans are tracked by UUID, so let's start by generating it.
	scan := &pb.Scan{}
	scan.ScanId = uuid.New().String()

	scanState := state{
		interests: make([]*mappedInterest, len(s.initialInterests)),
	}
	copy(scanState.interests, s.initialInterests)

	for _, interest := range scanState.interests {
		scan.Interests = append(scan.Interests, interest.interest)
	}
	scan.Interests = interests.Minify(scan.Interests)

	s.scans[scan.ScanId] = scanState

	return scan, nil
}

// ListInterests returns the interests for a given scan, i.e. the files or metadata
// that have to be fed to the Overlord for security scanning.
func (s *Server) ListInterests(ctx context.Context, req *pb.ListInterestsRequest) (*pb.ListInterestsResponse, error) {
	if req.GetPageToken() != "" {
		return nil, fmt.Errorf("token support is unimplemented")
	}
	scan, ok := s.scans[req.GetScanId()]
	if !ok {
		return nil, fmt.Errorf("unknown scan ID %s", req.GetScanId())
	}
	resp := &pb.ListInterestsResponse{}
	for _, i := range scan.interests {
		resp.Interests = append(resp.Interests, i.interest)
	}
	resp.Interests = interests.Minify(resp.Interests)
	return resp, nil
}

// ScanFiles runs security scan on a set of files, assuming they were actually
// needed by the backend minions.
func (s *Server) ScanFiles(ctx context.Context, req *pb.ScanFilesRequest) (*pb.ScanFilesResponse, error) {
	_, ok := s.scans[req.GetScanId()]
	if !ok {
		return nil, fmt.Errorf("unknown scan ID %s", req.GetScanId())
	}
	return nil, fmt.Errorf("unimplemented")
}
