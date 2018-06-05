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
	"io"
	"os"
	"strings"

	"github.com/golang/protobuf/ptypes"

	"github.com/google/minions/minions/vulners/dpkg"
	pb "github.com/google/minions/proto/minions"
	"golang.org/x/net/context"
)

// Minion that performs checks for known vulnerabilities in the software
// installed on the box.
type Minion struct {
	apiClient *Client // Vulners API client
}

// NewMinion creates a default vulners minion that connects to Vulners default
// API endpoints. It accepts an optional apiKey parameter which specifies which
// key to use when querying the Vulners APIs.
func NewMinion(apiKey string) *Minion {
	return &Minion{newClient(apiKey)}
}

// ListInitialInterests returns a list of files which might contain
// package information for parsing.
func (m Minion) ListInitialInterests(ctx context.Context, req *pb.ListInitialInterestsRequest) (*pb.ListInitialInterestsResponse, error) {
	dpkSstatus := pb.Interest{ // DPKG repo (for debian-like).
		DataType:      pb.Interest_METADATA_AND_DATA,
		PathRegexp:    "/var/lib/dpkg/status",
		ContentRegexp: ""}

	osReleaseEtc := pb.Interest{ // OS-release
		DataType:      pb.Interest_METADATA_AND_DATA,
		PathRegexp:    "/etc/os-release",
		ContentRegexp: ""}

	osReleaseUsrLib := pb.Interest{ // OS-release
		DataType:      pb.Interest_METADATA_AND_DATA,
		PathRegexp:    "/usr/lib/os-release",
		ContentRegexp: ""}

	rpmDatabase := pb.Interest{ // Used for RPM based systems.
		DataType:      pb.Interest_METADATA_AND_DATA,
		PathRegexp:    "/var/lib/rpm/*",
		ContentRegexp: ""}

	interests := []*pb.Interest{&dpkSstatus, &osReleaseEtc, &osReleaseUsrLib, &rpmDatabase}
	return &pb.ListInitialInterestsResponse{Interests: interests}, nil
}

// AnalyzeFiles will parse package databases, extract CPEs and query the
// vulners backend for security bugs.
func (m Minion) AnalyzeFiles(ctx context.Context, req *pb.AnalyzeFilesRequest) (*pb.AnalyzeFilesResponse, error) {
	// TODO(claudio): open files from the request instead of hardcoding this, so it's actually useful.
	// files := req.GetFiles()
	// TODO(claudio): add decent error management

	// First step: retrieve the OS version name and number
	// TODO(claudio): either get the /etc or the /usr/lib version
	f, err := os.Open("/etc/os-release")
	defer f.Close()
	distro, version, err := getOsAndversion(f)
	if err != nil {
		return nil, err
	}

	// Now read the package storage and build a map of installed packages
	df, err := os.Open("/var/lib/dpkg/status")
	defer df.Close()
	if err != nil {
		return nil, err // TODO(claudio): uniform error handling here (return error to grpc)
	}
	s := dpkg.NewScanner(df)

	var packages []string
	for entry, err := s.Scan(); err != io.EOF; entry, err = s.Scan() {
		if err != nil {
			panic(err)
		}
		p := []string{entry["package"], entry["version"], entry["architecture"]}
		pkg := strings.Join(p, " ")
		packages = append(packages, pkg)
	}

	// Now send the list of packages to the vulners API to get vulns
	response, err := m.apiClient.getVulnerabilitiesForPackages(distro, version, packages)
	if err != nil {
		return nil, err
	}

	// Now iterate over all packages that have been found vulnerable and return individual
	// findings for each bug for each package. Proto building time, woohoo!
	findings := []*pb.Finding{}
	for packageName, issues := range (*response).Data.Packages {
		for issueName, issueDetails := range issues {
			adv := &pb.Advisory{
				Reference:      issueName,
				Description:    strings.Join(issueDetails.CveList, ","),
				Recommendation: issueDetails.Fix,
			}
			source := &pb.Source{
				ScanId:        req.GetScanId(),
				Minion:        "Vulners",
				DetectionTime: ptypes.TimestampNow(),
			}
			resources := []*pb.Resource{&pb.Resource{
				Path:           "",
				AdditionalInfo: packageName,
			}}
			newFind := &pb.Finding{
				Advisory:            adv,
				VulnerableResources: resources,
				Source:              source,
				Accuracy:            pb.Finding_ACCURACY_AVERAGE, // Current trust level in vulners, may be adjusted based on distro in the future
				Severity:            pb.Finding_SEVERITY_UNKNOWN, // TODO(claudio): convert CVSS into severity
			}
			findings = append(findings, newFind)
		}
	}

	// We don't really need new interests as we know where the packages are
	// located sine day one, so let's just return results.
	resp := pb.AnalyzeFilesResponse{NewInterests: nil, Findings: findings}
	return &resp, nil
}
