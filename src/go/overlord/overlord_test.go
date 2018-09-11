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
	"testing"

	"github.com/google/minions/go/overlord/state"
	mpb "github.com/google/minions/proto/minions"
	pb "github.com/google/minions/proto/overlord"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/stretchr/testify/require"
)

func Test_CreateScan_returnsUuid(t *testing.T) {
	s, err := New(context.Background(), nil)
	require.NoError(t, err)

	resp, err := s.CreateScan(context.Background(), nil)
	require.NoError(t, err)
	require.NotEmpty(t, resp.GetScanId())
}

func Test_CreateScanAndListInterests_returnsInitialInterests(t *testing.T) {
	interest := &mpb.Interest{
		DataType:   mpb.Interest_METADATA_AND_DATA,
		PathRegexp: "/some/regexp",
	}
	interests := []*state.MappedInterest{
		&state.MappedInterest{interest, "fake_minion"},
	}
	s, err := New(context.Background(), nil)
	require.NoError(t, err)

	// Hard-plugging some initial interests in the overlord.
	s.initialInterests = interests
	resp, err := s.CreateScan(context.Background(), nil)
	require.NoError(t, err)
	require.Contains(t, resp.GetInterests(), interest)

	// Retrieve non existing scan
	req := &pb.ListInterestsRequest{ScanId: "Totally fake"}
	r, err := s.ListInterests(context.TODO(), req)
	require.Error(t, err)

	// Now retrieve interests for this scan.
	req = &pb.ListInterestsRequest{ScanId: resp.GetScanId()}
	r, err = s.ListInterests(context.TODO(), req)
	require.NoError(t, err)
	require.Contains(t, r.GetInterests(), interest)
}

func Test_INTERNAL_queriesMinions(t *testing.T) {
	i := &mpb.Interest{
		DataType:   mpb.Interest_METADATA_AND_DATA,
		PathRegexp: "/irrelevant",
	}
	interests := []*mpb.Interest{i}
	fm := &fakeMinionClient{interests: interests}
	minionClients := make(map[string]mpb.MinionClient)
	minionClients["fakeMinion"] = fm
	retrievedInterests, err := getInterestsFromMinions(context.Background(), minionClients)
	require.NoError(t, err)
	require.Equal(t, retrievedInterests[0].Interest, i)
}

type fakeMinionClient struct {
	interests []*mpb.Interest
}

func (m *fakeMinionClient) ListInitialInterests(ctx context.Context, req *mpb.ListInitialInterestsRequest, opts ...grpc.CallOption) (*mpb.ListInitialInterestsResponse, error) {
	return &mpb.ListInitialInterestsResponse{Interests: m.interests}, nil
}
func (m *fakeMinionClient) AnalyzeFiles(ctx context.Context, req *mpb.AnalyzeFilesRequest, opts ...grpc.CallOption) (*mpb.AnalyzeFilesResponse, error) {
	return nil, nil
}

// TODO: the overlord still needs plenty of unit tests
// Cases that are untested: rebuilding chunks, routing results to minion,
// state building through additional interests.
