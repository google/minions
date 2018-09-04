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
	"fmt"
	"log"

	"github.com/google/minions/go/overlord/interests"
	"github.com/google/uuid"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	mpb "github.com/google/minions/proto/minions"
	pb "github.com/google/minions/proto/overlord"
)

// Server implements the OverlordServer interface, the orchestrator of Minions' infrastructure.
type Server struct {
	minions          map[string]mpb.MinionClient // The minions we know about and their address
	initialInterests []*mappedInterest           // The initial interests all scans will get
	stateManager     StateManager                // Manages local stage between scans.
}

// mappedInterest stores the interest along with the address of the minion which expressed it.
type mappedInterest struct {
	interest *mpb.Interest
	minion   string
}

// New returns an initialized Server, which connects to a set of pre-specified minions
// to initialize them.
func New(ctx context.Context, minionAddresses []string, opts ...grpc.DialOption) (*Server, error) {
	server := &Server{
		minions:      make(map[string]mpb.MinionClient),
		stateManager: NewLocalStateManager(),
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
	interests, err := getInterestsFromMinions(ctx, server.minions)
	if err != nil {
		return nil, err
	}
	server.initialInterests = interests
	log.Printf("Initial interests: %d", len(server.initialInterests))
	return server, nil
}

func getInterestsFromMinions(ctx context.Context, minions map[string]mpb.MinionClient) ([]*mappedInterest, error) {
	var interests []*mappedInterest
	for name, m := range minions {
		// TODO(paradoxengine): most likely, a deadline here?
		intResp, err := m.ListInitialInterests(ctx, &mpb.ListInitialInterestsRequest{})
		if err != nil {
			return nil, err
		}
		for _, v := range intResp.GetInterests() {
			interests = append(interests, &mappedInterest{
				interest: v,
				minion:   name,
			})
		}
	}
	return interests, nil
}

// CreateScan set up a security scan which can then be fed files via ScanFiles.
// It returns a UUID identifying the scan from now on and the list of initial
// Interests.
func (s *Server) CreateScan(ctx context.Context, req *pb.CreateScanRequest) (*pb.Scan, error) {
	// Scans are tracked by UUID, so let's start by generating it.
	scan := &pb.Scan{}
	scan.ScanId = uuid.New().String()

	s.stateManager.CreateScan(scan.ScanId)
	for _, i := range s.initialInterests {
		s.stateManager.AddInterest(scan.ScanId, i.interest, i.minion)
	}

	knownInterests, err := s.stateManager.GetInterests(scan.ScanId)
	if err != nil {
		return nil, err
	}
	for _, interest := range knownInterests {
		scan.Interests = append(scan.Interests, interest.interest)
	}
	scan.Interests = interests.Minify(scan.Interests)

	return scan, nil
}

// ListInterests returns the interests for a given scan, i.e. the files or metadata
// that have to be fed to the Overlord for security scanning.
func (s *Server) ListInterests(ctx context.Context, req *pb.ListInterestsRequest) (*pb.ListInterestsResponse, error) {
	if req.GetPageToken() != "" {
		return nil, fmt.Errorf("token support is unimplemented")
	}
	if !s.stateManager.ScanExists(req.GetScanId()) {
		return nil, fmt.Errorf("unknown scan ID %s", req.GetScanId())
	}
	scanInterests, err := s.stateManager.GetInterests(req.GetScanId())
	if err != nil {
		return nil, err
	}
	resp := &pb.ListInterestsResponse{}
	for _, interest := range scanInterests {
		resp.Interests = append(resp.Interests, interest.interest)
	}
	resp.Interests = interests.Minify(resp.Interests)
	return resp, nil
}

// ScanFiles runs security scan on a set of files, assuming they were actually
// needed by the backend minions.
func (s *Server) ScanFiles(ctx context.Context, req *pb.ScanFilesRequest) (*pb.ScanFilesResponse, error) {
	scanID := req.GetScanId()
	if !s.stateManager.ScanExists(scanID) {
		return nil, fmt.Errorf("unknown scan ID %s", scanID)
	}

	if err := s.stateManager.AddFiles(req.GetScanId(), req.GetFiles()); err != nil {
		return nil, fmt.Errorf("error adding files to the scan state: %v", err)
	}

	// Now distribute all complete files for scanning.
	routedFiles := make(map[string][]*mpb.File)

	files, err := s.stateManager.GetFiles(scanID)
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		interestsForMinions, err := s.stateManager.GetInterests(scanID)
		if err != nil {
			return nil, err
		}
		for _, candidate := range interestsForMinions {
			if match, err := interests.IsMatching(candidate.interest, f); err != nil {
				return nil, err
			} else if !match {
				continue
			}

			isComplete := f.GetMetadata().GetSize() == int64(len(f.GetDataChunks()[0].GetData()))

			if candidate.interest.DataType == mpb.Interest_METADATA_AND_DATA && isComplete {
				routedFiles[candidate.minion] = append(routedFiles[candidate.minion], &mpb.File{
					Metadata: f.GetMetadata(),
					Data:     f.GetDataChunks()[0].GetData(), // Note we accumulate in the first chunk.
				})
			} else if candidate.interest.DataType == mpb.Interest_METADATA {
				// Send only metadata.
				routedFiles[candidate.minion] = append(routedFiles[candidate.minion], &mpb.File{
					Metadata: f.GetMetadata(),
				})
			}
		}
	}

	resp := &pb.ScanFilesResponse{}
	for address, files := range routedFiles {
		minion, present := s.minions[address]
		if !present {
			return nil, fmt.Errorf("interest expressed by a minion that is not known to the Overlord, %q", address)
		}
		minionResp, err := minion.AnalyzeFiles(ctx, &mpb.AnalyzeFilesRequest{
			ScanId: req.ScanId,
			Files:  files,
		})
		if err != nil {
			return nil, err
		}
		resp.Results = append(resp.Results, minionResp.GetFindings()...)
		resp.NewInterests = append(resp.NewInterests, minionResp.GetNewInterests()...)

		// Now export the new interests back to the state.
		for _, newInterest := range minionResp.GetNewInterests() {
			s.stateManager.AddInterest(scanID, newInterest, address)
		}
	}
	return resp, nil
}
