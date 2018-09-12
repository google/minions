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
	"sort"
	"strings"

  "github.com/google/minions/go/grpcutil"
	"github.com/google/minions/go/overlord/interests"
	"github.com/google/minions/go/overlord/state"
	"github.com/google/uuid"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	mpb "github.com/google/minions/proto/minions"
	pb "github.com/google/minions/proto/overlord"
)

// Server implements the OverlordServer interface, the orchestrator of Minions' infrastructure.
type Server struct {
	minions          map[string]mpb.MinionClient // The minions we know about and their address
	initialInterests []*state.MappedInterest     // The initial interests all scans will get
	stateManager     StateManager                // Manages local stage between scans.
}

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
	GetInterests(scanID string) ([]*state.MappedInterest, error)
	// RemoveFile atomically removes a given file from the state.
	RemoveFile(scanID string, file *pb.File) (bool, error)
	// ScanExists returns true if any state at all is known about the scan.
	ScanExists(scanID string) bool
}

// New returns an initialized Server, which connects to a set of pre-specified minions
// to initialize them. It accepts the path of a CA certificate to use to check the
// minions server certs
func New(ctx context.Context, minionAddresses []string, caCertPath string) (*Server, error) {
	server := &Server{
		minions:      make(map[string]mpb.MinionClient),
		stateManager: state.NewLocal(),
	}

	log.Println("Reaching out to all minions.")
	// Build map of minions.
	for _, addr := range minionAddresses {
		log.Printf("Reaching out to minion at %s\n", addr)
		host := strings.Split(addr, ":")[0] // If we have a port, extract hostname
		opts, err := grpcutil.GetSslClientOptions(host, caCertPath)
		if err != nil {
			return nil, err
		}
		c, err := grpc.Dial(addr, opts)
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

func getInterestsFromMinions(ctx context.Context, minions map[string]mpb.MinionClient) ([]*state.MappedInterest, error) {
	var interests []*state.MappedInterest
	for name, m := range minions {
		// TODO(paradoxengine): most likely, a deadline here?
		intResp, err := m.ListInitialInterests(ctx, &mpb.ListInitialInterestsRequest{})
		if err != nil {
			return nil, err
		}
		for _, v := range intResp.GetInterests() {
			interests = append(interests, &state.MappedInterest{
				Interest: v,
				Minion:   name,
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
		s.stateManager.AddInterest(scan.ScanId, i.Interest, i.Minion)
	}

	knownInterests, err := s.stateManager.GetInterests(scan.ScanId)
	if err != nil {
		return nil, err
	}
	for _, interest := range knownInterests {
		scan.Interests = append(scan.Interests, interest.Interest)
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
		resp.Interests = append(resp.Interests, interest.Interest)
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
			if match, err := interests.IsMatching(candidate.Interest, f); err != nil {
				return nil, err
			} else if !match {
				continue
			}

			isComplete := f.GetMetadata().GetSize() == int64(len(f.GetDataChunks()[0].GetData()))

			if candidate.Interest.DataType == mpb.Interest_METADATA_AND_DATA && isComplete {
				routedFiles[candidate.Minion] = append(routedFiles[candidate.Minion], &mpb.File{
					Metadata: f.GetMetadata(),
					Data:     f.GetDataChunks()[0].GetData(), // Note we accumulate in the first chunk.
				})
			} else if candidate.Interest.DataType == mpb.Interest_METADATA {
				// Send only metadata.
				routedFiles[candidate.Minion] = append(routedFiles[candidate.Minion], &mpb.File{
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
