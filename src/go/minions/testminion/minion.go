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
Package testminion contains a minion only to be used for testing.
Depending on how it's set up, it will always return a vulnerability
or will never do so.
*/
package testminion

import (
	"github.com/golang/protobuf/ptypes"
	pb "github.com/google/minions/proto/minions"
	"golang.org/x/net/context"
)

// Minion that always returns a vuln, or never does so based on
// the internal wantsVuln flag.
type Minion struct {
	paths     []string
	wantsVuln bool
}

// NewMinion creates a default test minion that returns a vuln or nothing based
// on the wantsVuln parameter, and announces Interests based on a set of paths.
func NewMinion(paths []string, wantsVuln bool) *Minion {
	return &Minion{paths, wantsVuln}
}

// ListInitialInterests returns a list of files which might contain
// package information for parsing.
func (m Minion) ListInitialInterests(ctx context.Context, req *pb.ListInitialInterestsRequest) (*pb.ListInitialInterestsResponse, error) {
	var interests []*pb.Interest
	for _, path := range m.paths {
		interests = append(interests, &pb.Interest{
			DataType:   pb.Interest_METADATA_AND_DATA,
			PathRegexp: path})
	}
	return &pb.ListInitialInterestsResponse{Interests: interests}, nil
}

// AnalyzeFiles will return a vuln (or not) regardless of the files it's passed.
func (m Minion) AnalyzeFiles(ctx context.Context, req *pb.AnalyzeFilesRequest) (*pb.AnalyzeFilesResponse, error) {
	findings := []*pb.Finding{}
	if m.wantsVuln {
		path := req.GetFiles()[0].GetMetadata().GetPath()
		adv := &pb.Advisory{
			Reference:      "FAKE_ADVISORY",
			Description:    "A fake advisory, for test purposes",
			Recommendation: "Once every full moon, drink orange juice",
		}
		src := &pb.Source{
			ScanId:        req.GetScanId(),
			Minion:        "Test minion",
			DetectionTime: ptypes.TimestampNow(),
		}
		res := []*pb.Resource{&pb.Resource{Path: path}}
		findings = append(findings, &pb.Finding{
			Advisory:            adv,
			VulnerableResources: res,
			Source:              src,
			Accuracy:            pb.Finding_ACCURACY_GREAT,
			Severity:            pb.Finding_SEVERITY_CRITICAL,
		})
	}
	resp := pb.AnalyzeFilesResponse{NewInterests: nil, Findings: findings}
	return &resp, nil
}
