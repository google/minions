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
Package vulners contains a minion that uses the Vulners API to perform
security scans on software packages installed on a system.

It does so by loading a list of all the software via the package
manager (currently only supporting linux) and sending the CPE it
builds to the Vulners backend.
*/
package vulners

import (
	"os"

	pb "github.com/google/minions/proto/minions"
	"golang.org/x/net/context"
)

// Minion that performs checks for known vulnerabilities in the software
// installed on the box.
type Minion struct {
}

// NewMinion creates a default vulners minion that connects to Vulners default
// API endpoints.
func NewMinion() *Minion {
	return &Minion{NewClient()}
}

// ListInitialInterests returns a list of files which might contain
// package information for parsing.
func (m Minion) ListInitialInterests(ctx context.Context, req *pb.ListInitialInterestsRequest) (*pb.ListInitialInterestsResponse, error) {
	dpkgstatus := pb.Interest{ // Used for debian systems.
		DataType:      pb.Interest_METADATA_AND_DATA,
		PathRegexp:    "/var/lib/dpkg/status",
		ContentRegexp: ""}

	rpmdatabase := pb.Interest{ // Used for RPM based systems.
		DataType:      pb.Interest_METADATA_AND_DATA,
		PathRegexp:    "/var/lib/rpm/*",
		ContentRegexp: ""}

	interests := []*pb.Interest{&dpkgstatus, &rpmdatabase}
	return &pb.ListInitialInterestsResponse{Interests: interests}, nil
}

// AnalyzeFiles will parse package databases, extract CPEs and query the
// vulners backend for security bugs.
func (m Minion) AnalyzeFiles(ctx context.Context, req *pb.AnalyzeFilesRequest) (*pb.AnalyzeFilesResponse, error) {
	// Accumulator for the findings through the scan.
	findings := []*pb.Finding{}

	// Printf debugging like it's 1983
	files := req.GetFiles()
	print(files)

	// TODO(claudio): open the file from the request.
	f, err := os.Open("/var/lib/dpkg/status")
	if err != nil {
		panic(err) // TODO(claudio): uniform error handling here (return error to grpc)
	}

	// TODO(parse files)
	// Accumulate vulns inside findings (with proper conversion)

	// We don't really need new interests as we know where the packages are
	// located sine day one, so let's just return results.
	resp := pb.AnalyzeFilesResponse{NewInterests: nil, Findings: findings}
	return &resp, nil
}
