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


// Package tomcat is a minion which is looking for vulnerabilities in tomcat
// configuration files.
package tomcat

import (
	"encoding/xml"
	"fmt"
	"path"
	"regexp"
	"strings"
)

// Advisories that are used by the tomcat Minion.
var (
	DefaultCredentials = &fpb.Advisory{
		Reference:      "tomcat_weak_manager_credentials",
		Description:    "A user with access to the Tomcat manager has defaults credentials.",
		Recommendation: "Change the password for this user.",
	}
)

var (
	serverRe  = regexp.MustCompile(`/conf/server\.xml$`)
	managerRe = regexp.MustCompile(`/(?:host-)?manager/WEB-INF/web\.xml$`)
	usersRe   = regexp.MustCompile(`/conf/tomcat-users\.xml$`)
)

const maxBaseDirCount = 100

// Minion is the implementation of minion.Minion interface.
type Minion struct{}

// ListInitialInterests asks for the main tomcat configuration file.
func (m *Minion) ListInitialInterests(ctx context.Context, req *pb.ListInitialInterestsRequest) (*pb.ListInitialInterestsResponse, error) {
	return &pb.ListInitialInterestsResponse{
		Interests: []*pb.Interest{
			&pb.Interest{
				PathRegexp: serverRe.String(),
				DataType:   pb.Interest_METADATA_AND_DATA,
			},
		},
	}, nil
}

// AnalyzeFiles looks for users with default credentials and access to the tomcat manager.
func (m *Minion) AnalyzeFiles(ctx context.Context, req *pb.AnalyzeFilesRequest) (*pb.AnalyzeFilesResponse, error) {
	for _, file := range req.GetFiles() {
		if file.GetMetadata() == nil {
			return nil, fmt.Errorf("tomcat: minion received file with no metadata")
		}

		switch {

		case serverRe.MatchString(file.GetMetadata().Path):
			// If the initial configuration is received, then ask
			// for the configuration of Manager applications in the
			// application directories defined in the config.
			directories, err := getDirectories(ctx, file)
			if err != nil {
				return nil, err
			}
			resp := &pb.AnalyzeFilesResponse{}
			for _, dir := range directories {
				resp.NewInterests = append(resp.NewInterests, &pb.Interest{
					// METADATA only is enough to check if
					// the manager application is present.
					DataType:   pb.Interest_METADATA,
					PathRegexp: regexp.QuoteMeta(dir) + managerRe.String(),
				})
			}
			return resp, nil

		case managerRe.MatchString(file.GetMetadata().Path):
			// If the configuration of a manager is received, then
			// ask for the credentials config.

			// Strip 4 directories from the path - what is left
			// should be the base directory of tomcat.
			baseDir := file.GetMetadata().Path
			for i := 0; i < 4; i++ {
				baseDir = path.Dir(baseDir)
			}
			return &pb.AnalyzeFilesResponse{
				NewInterests: []*pb.Interest{
					&pb.Interest{
						DataType:   pb.Interest_METADATA_AND_DATA,
						PathRegexp: regexp.QuoteMeta(baseDir) + usersRe.String(),
					},
				},
			}, nil

		case usersRe.MatchString(file.GetMetadata().Path):
			// Parse the credentials and search for default ones
			// with the access to the manager.
			findings, err := checkUsers(ctx, file)
			if err != nil {
				return nil, err
			}
			ts := ptypes.TimestampNow()
			for _, f := range findings {
				f.Source = &fpb.Source{
					ScanId:        req.ScanId,
					Minion:        "tomcat",
					DetectionTime: ts,
				}
			}
			return &pb.AnalyzeFilesResponse{
				Findings: findings,
			}, nil
		}
	}
	return &pb.AnalyzeFilesResponse{}, nil
}

type host struct {
	Base string `xml:"appBase,attr"`
}

type server struct {
	XMLName xml.Name `xml:"Server"`
	Hosts   []host   `xml:"Service>Engine>Host"`
}

// getDirectories parses the main tomcat configuration file and returns
// application directories declared in it.
func getDirectories(ctx context.Context, file *pb.File) ([]string, error) {
	var dirs []string
	document := &server{}
	if err := xml.Unmarshal(file.Data, document); err != nil {
		return nil, err
	}
	for _, host := range document.Hosts {
		if len(dirs) >= maxBaseDirCount {
			return nil, fmt.Errorf("more than 100 webapp directories declared in the tomcat config file")
		}
		dirs = append(dirs, host.Base)
	}
	return dirs, nil
}

type user struct {
	Name     string `xml:"username,attr"`
	Password string `xml:"password,attr"`
	Roles    string `xml:"roles,attr"`
}

type tomcatUsers struct {
	XMLName xml.Name `xml:"tomcat-users"`
	Users   []user   `xml:"user"`
}

// checkUsers parses the file defining the credentials and returns a Finding for
// each user having access to manager and using default credentials.
func checkUsers(ctx context.Context, file *pb.File) ([]*fpb.Finding, error) {
	var (
		defaultCredentials = []struct {
			username string
			password string
		}{
			{"admin", "admin"},
			{"admin", "tomcat"},
			{"tomcat", "tomcat"},
			{"root", "root"},
			{"j2deployer", "j2deployer"},
			{"ovwebusr", "OvW*busr1"},
			{"cxsdk", "kdsxc"},
			{"root", "owaspbwa"},
			{"ADMIN", "ADMIN"},
			{"xampp", "xampp"},
			{"tomcat", "s4cret"},
			{"both", "tomcat"},
			{"role1", "tomcat"},
		}

		findings []*fpb.Finding
		document = &tomcatUsers{}
	)

	if err := xml.Unmarshal(file.Data, document); err != nil {
		return nil, err
	}

	isManager := func(u user) bool {
		for _, role := range strings.Split(u.Roles, ",") {
			switch role {
			case "manager-gui", "manager-script", "manager-jmx":
				return true
			}
		}
		return false
	}

	for _, user := range document.Users {
		for _, cred := range defaultCredentials {
			if cred.username == user.Name && cred.password == user.Password && isManager(user) {
				findings = append(findings, &fpb.Finding{
					Accuracy: fpb.Finding_ACCURACY_FIRM,
					Severity: fpb.Finding_SEVERITY_HIGH,
					Advisory: DefaultCredentials,
					VulnerableResources: []*fpb.Resource{
						&fpb.Resource{
							Path:           file.GetMetadata().Path,
							AdditionalInfo: fmt.Sprintf("user %q", user.Name),
						},
					},
				})
			}
		}
	}
	return findings, nil
}
