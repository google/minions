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
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/minions/go/minions/vulners/dpkg"
	"github.com/google/minions/go/minions/vulners/rpm"
	pb "github.com/google/minions/proto/minions"
	"github.com/patrickmn/go-cache"
	"golang.org/x/net/context"
)

// Minion that performs checks for known vulnerabilities in the software
// installed on the box.
type Minion struct {
	apiClient VulnerabilityClient // API client to fetch vulnerabilities
	tmpCache  *cache.Cache
}

// VulnerabilityClient is a client to fetch vulnerability data for a set of packages
// given an operating system and version
type VulnerabilityClient interface {
	GetVulnerabilitiesForPackages(string, string, []string) (*VulnResponse, error)
}

// state represents the internal state of the minions, used to track
// files of the same. It is always associated to a ScanID.
type state struct {
	version  string
	distro   string
	packages []string
	init     bool
}

// NewMinion creates a default vulners minion that connects to Vulners default
// API endpoints. It accepts an optional apiKey parameter which specifies which
// key to use when querying the Vulners APIs.
func NewMinion(apiKey string) *Minion {
	return &Minion{newClient(apiKey), cache.New(5*time.Minute, 10*time.Minute)}
}

// ListInitialInterests returns a list of files which might contain
// package information for parsing.
func (m Minion) ListInitialInterests(ctx context.Context, req *pb.ListInitialInterestsRequest) (*pb.ListInitialInterestsResponse, error) {
	osReleaseEtc := interest("/etc/os-release")        // OS Release with OS and version info
	osReleaseUsrLib := interest("/usr/lib/os-release") // Alternative location for the OS release
	dpkSstatus := interest("/var/lib/dpkg/status")     // DPKG repo (for debian-like).
	rpmDatabase := interest("/var/lib/rpm/Packages")   // RPM database
	interests := []*pb.Interest{&dpkSstatus, &osReleaseEtc, &osReleaseUsrLib, &rpmDatabase}
	return &pb.ListInitialInterestsResponse{Interests: interests}, nil
}

func interest(name string) pb.Interest {
	return pb.Interest{ // DPKG repo (for debian-like).
		DataType:   pb.Interest_METADATA_AND_DATA,
		PathRegexp: "/var/lib/dpkg/status"}
}

// AnalyzeFiles will parse package databases, extract CPEs and query the
// vulners backend for security bugs.
func (m Minion) AnalyzeFiles(ctx context.Context, req *pb.AnalyzeFilesRequest) (*pb.AnalyzeFilesResponse, error) {
	// TODO(paradoxengine): add decent error management

	// Init with an empty state if needed.
	if !m.hasState(req.GetScanId()) {
		m.setState(req.GetScanId(), &state{init: true})
	}

	// Main loop, builds the state and parses all incoming files.
	for _, f := range req.Files {
		path := f.GetMetadata().GetPath()
		switch path {
		case "/etc/os-release", "/usr/lib/os-release":
			err := m.extractOsAndSetState(req, f)
			if err != nil {
				return nil, err // TODO(paradoxengine): uniform error handling here (return error to grpc)
			}
		case "/var/lib/dpkg/status":
			var err error
			err = m.getDpkgPackagesAndSetState(req.GetScanId(), bytes.NewReader(f.GetData()))
			if err != nil {
				return nil, err // TODO(paradoxengine): uniform error handling here (return error to grpc)
			}
		case "/var/lib/rpm/Packages":
			// The RPM libraries need an actual file :-(
			dir, err := ioutil.TempDir("", "RPMDATABASE")
			if err != nil {
				log.Fatal(err)
			}
			defer os.RemoveAll(dir) // clean up
			tmpfn := filepath.Join(dir, "Packages")
			if err := ioutil.WriteFile(tmpfn, f.GetData(), 0666); err != nil {
				log.Fatal(err)
			}
			err = m.getRpmPackagesAndSetState(req.GetScanId(), tmpfn)
			if err != nil {
				return nil, err // TODO(paradoxengine): uniform error handling here (return error to grpc)
			}
		default:
			log.Printf("Unknown path: %s. Won't analyze file", path)
		}
	}

	findings := []*pb.Finding{}

	s, err := m.getState(req.GetScanId())
	if err != nil {
		return nil, err
	}

	if len(s.packages) > 0 {
		// Let's see if we already have distro and version.
		distro, version, err := m.getDistroVersionFromState(req.GetScanId())
		if err != nil {
			return nil, err
		}
		// If the OS details have been parsed already then let's have a look at the installed stuff.
		if distro != "" {
			// Now send the list of packages to the vulners API to get vulns
			response, err := m.apiClient.GetVulnerabilitiesForPackages(distro, version, s.packages)
			if err != nil {
				return nil, err
			}
			// Now iterate over all packages that have been found vulnerable and return individual
			// findings for each bug for each package. Proto building time, woohoo!
			for packageName, issues := range (*response).Data.Packages {
				for issueName, issueDetails := range issues {
					findings = append(findings, convertFinding(packageName, issues, issueName, issueDetails, req.GetScanId()))
				}
			}
		}
	}

	// We don't really need new interests as we know where the packages are
	// located sine day one, so let's just return results.
	resp := pb.AnalyzeFilesResponse{NewInterests: nil, Findings: findings}
	return &resp, nil
}

// extractOsAndSetState takes the required data out of the request and sets the
// scan state accordingly.
func (m *Minion) extractOsAndSetState(req *pb.AnalyzeFilesRequest, f *pb.File) error {
	// Extracting OS details, fetching data.
	distro, version, err := getOsAndversion(bytes.NewReader(f.GetData()))
	if err != nil {
		return err
	}
	state, err := m.getState(req.GetScanId())
	if err != nil {
		return err
	}
	state.version = version
	state.distro = distro
	return m.setState(req.GetScanId(), state)
}

func (m *Minion) getDistroVersionFromState(scanID string) (string, string, error) {
	s, err := m.getState(scanID)
	if err != nil {
		return "", "", err
	}
	return s.distro, s.version, nil
}

// setState atomically sets the state of a minion during a scan.
func (m *Minion) setState(scanID string, state *state) error {
	m.tmpCache.Set(scanID, state, 0)
	return nil
}

// getState atomically gets the state of a minion during a scan.
func (m *Minion) getState(scanID string) (*state, error) {
	s, found := m.tmpCache.Get(scanID)
	if !found {
		return nil, errors.New("did not find any state for this scan")
	}
	return s.(*state), nil
}

func (m *Minion) hasState(scanID string) bool {
	_, found := m.tmpCache.Get(scanID)
	return found
}

// convertFinding builds an internal representation of the fining from the vulners
// data. Note that vulners provides an array of vulnPackage, but we really only
// care about the first one at this point, so we simplify the code.
func convertFinding(packageName string, issues map[string][]vulnPackage, issueName string, issueDetails []vulnPackage, scanID string) *pb.Finding {
	adv := &pb.Advisory{
		Reference:      issueName,
		Description:    strings.Join(issueDetails[0].CveList, ","),
		Recommendation: issueDetails[0].Fix,
	}
	source := &pb.Source{
		ScanId:        scanID,
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
	return newFind
}

// getRpmPackagesAndSetState parses the DPKG packages and extends the state with
// the new known packages.
func (m *Minion) getDpkgPackagesAndSetState(scanID string, df io.Reader) error {
	pkgs, err := getDpkgPackages(df)
	s, err := m.getState(scanID)
	if err != nil {
		return err
	}
	s.packages = append(s.packages, pkgs...)
	return m.setState(scanID, s)
}

// Analyzes the dpkg database and returns a list of packages, versions and
// architectures suitable to be fed in vulners.
func getDpkgPackages(df io.Reader) ([]string, error) {
	s := dpkg.NewScanner(df)

	var packages []string
	for entry, err := s.Scan(); err != io.EOF; entry, err = s.Scan() {
		if err != nil {
			return nil, err
		}
		// Note: my Java self feels this really needed a data class rather than a string
		// but I'm told this is more idiomatic and what do I know about Go.
		p := []string{entry["package"], entry["version"], entry["architecture"]}
		pkg := strings.Join(p, " ")
		packages = append(packages, pkg)
	}
	return packages, nil
}

// getRpmPackagesAndSetState parses the RPM packages and extends the state with
// the new known packages.
func (m *Minion) getRpmPackagesAndSetState(scanID string, dbPath string) error {
	pkgs, err := getRpmPackages(dbPath)
	s, err := m.getState(scanID)
	if err != nil {
		return err
	}
	s.packages = append(s.packages, pkgs...)
	return m.setState(scanID, s)
}

// Analyzes the RPM database and returns a list of packages, versions and
// architectures suitable to be fed in vulners.
func getRpmPackages(dbPath string) ([]string, error) {
	var packages []string
	pkgs, err := rpm.ReadDbAndCleanup(dbPath)
	if err != nil {
		return nil, err
	}
	for _, p := range pkgs {
		pkg := []string{p.Name, p.Version, p.Architecture}
		packages = append(packages, strings.Join(pkg, " "))
	}
	return packages, nil
}
