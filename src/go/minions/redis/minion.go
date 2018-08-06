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
Package redis contains a Redis focused minion, which checks
Redis-related security configurations.
The Redis security model is simple: if you can access the system, it's over.
Networking bindings and requirepass are the relevant items. It should be noted
that since version 3.2 there is a "protected mode" when the system is
bound to all interfaces and has no password.
*/
package redis

import (
	"bufio"
	"bytes"
	"os"
	"regexp"
	"strings"

	"github.com/golang/protobuf/ptypes"
	pb "github.com/google/minions/proto/minions"
	"github.com/phayes/permbits"
	"golang.org/x/net/context"
)

// Minion checking for Redis configuration issues.
type Minion struct {
}

// NewMinion creates a default Redis Minion.
func NewMinion() *Minion {
	return &Minion{}
}

// ListInitialInterests returns a list of files which might contain
// package information for parsing.
func (m Minion) ListInitialInterests(ctx context.Context, req *pb.ListInitialInterestsRequest) (*pb.ListInitialInterestsResponse, error) {
	interests := []*pb.Interest{
		interest("/etc/redis/.*\\.conf"),
		interest("/usr/local/etc/redis/.*\\.conf"),
	}
	return &pb.ListInitialInterestsResponse{Interests: interests}, nil
}

func interest(name string) *pb.Interest {
	return &pb.Interest{
		DataType:   pb.Interest_METADATA_AND_DATA,
		PathRegexp: name}
}

// AnalyzeFiles will parse the provided configuration file and flag issues.
func (m Minion) AnalyzeFiles(ctx context.Context, req *pb.AnalyzeFilesRequest) (*pb.AnalyzeFilesResponse, error) {
	// IMPORTANT: The current algorith, is pretty naive, and just assumes that all the configs
	// that we identify are part of a single redis installation. That's probably true in most
	// cases, but not all. A better approach would be to identify "root" configs and recurse
	// all include statements by issuing additional interests.
	// If this minion is interesting enough we can look into it.

	// The only files we expect to see are redis configs, which are plaintext files.
	findings := []*pb.Finding{}

	foundRequirePass := false
	bindClauseFound := false // If none is found, then by default Redis binds to all interfaces.
	boundOutsideLocalhost := false
	protectedModeDisabled := false

	for _, f := range req.GetFiles() {
		confScanner := bufio.NewScanner(bytes.NewReader(f.GetData()))
		for confScanner.Scan() {
			line := strings.Trim(confScanner.Text(), " ")
			// We just skip all coments.
			if !strings.HasPrefix(line, "#") {
				if strings.HasPrefix(line, "bind") {
					bindClauseFound = true
					for _, ip := range strings.Fields(line)[1:] {
						isLocalhost, err := regexp.MatchString(
							"^localhost$|^127(?:\\.[0-9]+){0,2}\\.[0-9]+$|^(?:0*\\:)*?:?0*1$", ip)
						if err != nil {
							return nil, err
						}
						if !isLocalhost {
							boundOutsideLocalhost = true
						}
					}
				}
				if strings.HasPrefix(line, "requirepass") {
					// TODO(paradoxengine) Check if there is an actual password!
					foundRequirePass = true
					// Checking if we have identified the requirepass statement inside a
					// world readable file.
					pbits := permbits.FileMode(os.FileMode(f.GetMetadata().GetPermissions()))
					if pbits.OtherRead() {
						findings = append(findings, readableRequirePassFinding(req.GetScanId(), f))
					}
					// TODO(paradoxengine): Bruteforce trivial passwords? Maybe complain if lenght < 5?
				}
				if strings.HasPrefix(line, "protected-mode") {
					// Check if protectedModeDisabled. Given that this has been around since
					// version 3.2, which is somewhere in 2016, it's fair to expect the
					// feature to be there (and enabled by default).
					tk := strings.Fields(line)
					if len(tk) > 1 && tk[1] == "no" {
						protectedModeDisabled = true
					}
				}
			}
		}
	}

	if (!bindClauseFound || boundOutsideLocalhost) && !foundRequirePass && protectedModeDisabled {
		findings = append(findings, unprotectedFinding(req.GetScanId()))
	}

	resp := pb.AnalyzeFilesResponse{NewInterests: nil, Findings: findings}
	return &resp, nil
}

// unprotectedFinding generates a finding flagging the fact that the redis
// server has been left unprotected on the network.
func unprotectedFinding(scanID string) *pb.Finding {
	adv := &pb.Advisory{
		Reference:      "MINIONS_REDIS_02",
		Description:    "A Redis database is configured to be bound to the network without a password.",
		Recommendation: "Set a password using requirepass, re-enable protected mode or bind to localhost only.",
	}
	res := []*pb.Resource{&pb.Resource{}}
	return &pb.Finding{
		Advisory:            adv,
		VulnerableResources: res,
		Source:              defaultMinionSource(scanID),
		// Due to our ineffective config files parsing (missing include), we cannot trust this finding
		// a whole lot: we might be missing files that specify additional security configs.
		Accuracy: pb.Finding_ACCURACY_AVERAGE,
		Severity: pb.Finding_SEVERITY_CRITICAL, // This is effectively an RCE.
	}
}

// readableRequirePassFinding generates a finding to report a world readabe
// config containing the requirepass directive (and thus insecure)
func readableRequirePassFinding(scanID string, f *pb.File) *pb.Finding {
	path := f.GetMetadata().GetPath()
	adv := &pb.Advisory{
		Reference: "MINIONS_REDIS_01",
		Description: "A Redis configuration file contaning the RequirePass " +
			"directive is world readable, which makes it easy to leak the password.",
		Recommendation: "Restrict access to the configuration file so it is not world readable",
	}
	res := []*pb.Resource{&pb.Resource{Path: path}}
	return &pb.Finding{
		Advisory:            adv,
		VulnerableResources: res,
		Source:              defaultMinionSource(scanID),
		Accuracy:            pb.Finding_ACCURACY_FIRM,
		Severity:            pb.Finding_SEVERITY_MEDIUM,
	}
}

func defaultMinionSource(scanID string) *pb.Source {
	return &pb.Source{
		ScanId:        scanID,
		Minion:        "Redis configuration check",
		DetectionTime: ptypes.TimestampNow(),
	}
}
