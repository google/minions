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
Package passwdfile implements a minion that looks for simple issues within
/etc/passwd and /etc/shadow files.

It contains functions that allow one to check if users can login without
passwords, use weak hashes or are not root, but their uid is 0.

It also checks whether those files have insecure UNIX permissions.
*/
package passwdfile

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Advisories that are used by the passwdfile Minion.
var (
	PasswdPermissions = &fpb.Advisory{
		Reference:      "passwd_permissions",
		Description:    "/etc/passwd file has permissions that are too wide.",
		Recommendation: "Change the permissions of /etc/passwd to 0644.",
	}
	PasswdEmptyHash = &fpb.Advisory{
		Reference:      "passwd_empty_hash",
		Description:    "User has an empty password",
		Recommendation: "Set up a password for the user",
	}
	PasswdWeakHashType = &fpb.Advisory{
		Reference:      "passwd_weak_hash_type",
		Description:    "User uses weak hash function for the hash of his password.",
		Recommendation: "Change the hash function to SHA512.",
	}
	PasswdBackdoor = &fpb.Advisory{
		Reference:   "passwd_backdoor",
		Description: "A user which is not root has uid 0.",
	}
	ShadowPermissions = &fpb.Advisory{
		Reference:      "shadow_permissions",
		Description:    "/etc/shadow file has permissions that are too wide.",
		Recommendation: "Change the permissions of /etc/shadow to 0640.",
	}
	ShadowEmptyHash = &fpb.Advisory{
		Reference:      "shadow_empty_hash",
		Description:    "User has an empty password.",
		Recommendation: "Set up a password for the user.",
	}
	ShadowWeakHashType = &fpb.Advisory{
		Reference:      "shadow_weak_hash_type",
		Description:    "User uses weak hash for the hash of his password.",
		Recommendation: "Change the hash function to SHA512.",
	}
)

// Minion is the implementation of minion.Minion interface.
type Minion struct{}

// ListInitialInterests returns the initial interests of a Minion.
func (m *Minion) ListInitialInterests(ctx context.Context, req *pb.ListInitialInterestsRequest) (*pb.ListInitialInterestsResponse, error) {
	return &pb.ListInitialInterestsResponse{
		Interests: []*pb.Interest{
			&pb.Interest{
				PathRegexp: "^/etc/passwd$",
				DataType:   pb.Interest_METADATA_AND_DATA,
			},
			&pb.Interest{
				PathRegexp: "^/etc/shadow$",
				DataType:   pb.Interest_METADATA_AND_DATA,
			},
		},
	}, nil
}

// AnalyzeFiles looks for /etc/passwd and /etc/shadow files in the
// AnalyzeFilesRequest. It then returns security issues found in those files as
// Findings in pb.AnalyzeFilesResponse.
func (m *Minion) AnalyzeFiles(ctx context.Context, req *pb.AnalyzeFilesRequest) (*pb.AnalyzeFilesResponse, error) {
	var allFindings []*fpb.Finding

	for _, file := range req.GetFiles() {
		switch file.GetMetadata().Path {
		case "/etc/passwd":
			findings, err := AnalyzePasswd(file)
			if err != nil {
				return nil, err
			}
			allFindings = append(allFindings, findings...)
		case "/etc/shadow":
			findings, err := AnalyzeShadow(file)
			if err != nil {
				return nil, err
			}
			allFindings = append(allFindings, findings...)
		}
	}

	ts := ptypes.TimestampNow()
	// Update Findings with correct Source.
	for _, f := range allFindings {
		f.Source = &fpb.Source{
			ScanId:        req.ScanId,
			Minion:        "passwdfile",
			DetectionTime: ts,
		}
	}

	return &pb.AnalyzeFilesResponse{
		Findings: allFindings,
	}, nil
}

// AnalyzePasswd looks for security issues in the /etc/passwd file and reports
// them as Findings.
func AnalyzePasswd(file *pb.File) ([]*fpb.Finding, error) {
	var findings []*fpb.Finding

	if md := file.GetMetadata(); md != nil && !ArePasswdPermissionsSecure(md) {
		findings = append(findings, &fpb.Finding{
			Accuracy: fpb.Finding_ACCURACY_FIRM,
			Severity: fpb.Finding_SEVERITY_HIGH,
			Advisory: PasswdPermissions,
			VulnerableResources: []*fpb.Resource{
				&fpb.Resource{
					Path:           "/etc/passwd",
					AdditionalInfo: fmt.Sprintf("current permissions: %#o.", file.GetMetadata().Permissions),
				},
			},
		})
	}

	scanner := bufio.NewScanner(bytes.NewReader(file.Data))
	for scanner.Scan() {
		user, err := NewUser(scanner.Text())
		if err != nil {
			return nil, err
		}

		// Check if user can login without a password.
		// Average accuracy is assigned as we are not checking if there
		// is any service that the user can log into.
		if user.PasswordHash == "" {
			findings = append(findings, &fpb.Finding{
				Accuracy: fpb.Finding_ACCURACY_AVERAGE,
				Severity: fpb.Finding_SEVERITY_MEDIUM,
				Advisory: PasswdEmptyHash,
				VulnerableResources: []*fpb.Resource{
					&fpb.Resource{
						Path:           "/etc/passwd",
						AdditionalInfo: fmt.Sprintf("username: %s", user.Username),
					},
				},
			})
		}

		if !user.UsesShadowFile() && user.PasswordHash.UsesWeakHashing() {
			findings = append(findings, &fpb.Finding{
				Accuracy: fpb.Finding_ACCURACY_FIRM,
				Severity: fpb.Finding_SEVERITY_LOW,
				Advisory: PasswdWeakHashType,
				VulnerableResources: []*fpb.Resource{
					&fpb.Resource{
						Path:           "/etc/passwd",
						AdditionalInfo: fmt.Sprintf("username: %s", user.Username),
					},
				},
			})
		}

		if user.IsBackdooredRoot() {
			findings = append(findings, &fpb.Finding{
				Accuracy: fpb.Finding_ACCURACY_GREAT,
				Severity: fpb.Finding_SEVERITY_HIGH,
				Advisory: PasswdBackdoor,
				VulnerableResources: []*fpb.Resource{
					&fpb.Resource{
						Path:           "/etc/passwd",
						AdditionalInfo: fmt.Sprintf("username: %s", user.Username),
					},
				},
			})
		}
	}
	return findings, nil
}

// AnalyzeShadow looks for security issues in the /etc/shadow file and reports
// them as Findings.
func AnalyzeShadow(file *pb.File) ([]*fpb.Finding, error) {
	var findings []*fpb.Finding

	if md := file.GetMetadata(); md != nil && !AreShadowPermissionsSecure(md) {
		findings = append(findings, &fpb.Finding{
			Accuracy: fpb.Finding_ACCURACY_FIRM,
			Severity: fpb.Finding_SEVERITY_HIGH,
			Advisory: ShadowPermissions,
			VulnerableResources: []*fpb.Resource{
				&fpb.Resource{
					Path:           "/etc/shadow",
					AdditionalInfo: fmt.Sprintf("current permissions: %#o.", file.GetMetadata().Permissions),
				},
			},
		})
	}

	scanner := bufio.NewScanner(bytes.NewReader(file.Data))
	for scanner.Scan() {
		shadow, err := NewShadowInfo(scanner.Text())
		if err != nil {
			return nil, err
		}

		// Check if user can login without a password.
		if shadow.PasswordHash == "" {
			findings = append(findings, &fpb.Finding{
				Accuracy: fpb.Finding_ACCURACY_AVERAGE,
				Severity: fpb.Finding_SEVERITY_MEDIUM,
				Advisory: ShadowEmptyHash,
				VulnerableResources: []*fpb.Resource{
					&fpb.Resource{
						Path:           "/etc/shadow",
						AdditionalInfo: fmt.Sprintf("userame: %s", shadow.Username),
					},
				},
			})
		}

		if shadow.PasswordHash.UsesWeakHashing() {
			findings = append(findings, &fpb.Finding{
				Accuracy: fpb.Finding_ACCURACY_FIRM,
				Severity: fpb.Finding_SEVERITY_LOW,
				Advisory: ShadowWeakHashType,
				VulnerableResources: []*fpb.Resource{
					&fpb.Resource{
						Path:           "/etc/shadow",
						AdditionalInfo: fmt.Sprintf("userame: %s", shadow.Username),
					},
				},
			})
		}
	}
	return findings, nil
}

// ArePasswdPermissionsSecure checks the permissions of the /etc/passwd file.
// It returns false when there are issues with the permissions (any of g+w, o+w
// is set), and true otherwise.
func ArePasswdPermissionsSecure(passwd *pb.FileMetadata) bool {
	return passwd.Permissions&0022 == 0
}

// AreShadowPermissionsSecure checks the permissions of the /etc/shadow file.
// It returns false when there are issues with the permissions (any of g+w, o+w,
// o+r is set), and true otherwise.
func AreShadowPermissionsSecure(shadow *pb.FileMetadata) bool {
	return shadow.Permissions&0026 == 0
}

// Days represents time interval measured in days.
type Days int

// NewDays returns Days that represents the number of days given as
// duration. Returns -1 if given string is empty.
func NewDays(duration string) (Days, error) {
	if duration == "" {
		return -1, nil
	}

	days, err := strconv.Atoi(duration)
	if err != nil {
		return -1, err
	}
	return Days(days), nil
}

// HashType represent a type of hash.
type HashType int

// Various hash types used in /etc/passwd and /etc/shadow files.
const (
	MD5 HashType = iota
	BLOWFISH
	SHA256
	SHA512
	DES
)

// PasswordHash is a type used to store a hash of password.
type PasswordHash string

// UsesWeakHashing checks if the password was hashed using MD5 or DES.
func (hash PasswordHash) UsesWeakHashing() bool {
	if hash == "" || hash.IsDisabled() {
		return false
	}
	hashType := hash.GetHashType()
	return hashType == MD5 || hashType == DES
}

// IsDisabled checks if the password is disabled, which is typically done
// by prepending the hash with ! or *.
func (hash PasswordHash) IsDisabled() bool {
	passwd := string(hash)
	return strings.HasPrefix(passwd, "!") || strings.HasPrefix(passwd, "*")
}

// GetHashType returns the type of hash used by the PasswordHash.
func (hash PasswordHash) GetHashType() HashType {
	hashStr := string(hash)
	switch {
	case strings.HasPrefix(hashStr, "$1$"):
		return MD5
	case strings.HasPrefix(hashStr, "$2a$"):
		return BLOWFISH
	case strings.HasPrefix(hashStr, "$5$"):
		return SHA256
	case strings.HasPrefix(hashStr, "$6$"):
		return SHA512
	}
	return DES
}

// ShadowInfo represents en entry (line) from the /etc/shadow file.
type ShadowInfo struct {
	Username       string       // Username from /etc/passwd that this information refers to.
	PasswordHash   PasswordHash // Hash of the password, as in `man 3 crypt`.
	LastChangeDate time.Time    // Date of last password change. In /etc/shadow it is a number of days since 01/01/1970. Empty value from /etc/shadow is represented as zero value of time.Time and means that the aging features are disabled. Value of 01/01/1970 means that the user should change the password on the next login.
	MinimumAge     Days         // How long user have to wait before being allowed to change password. -1 and 0 mean that there is no minimum age.
	MaximumAge     Days         // User will have to change the password after that time. -1 means that there are no maximum pasword age, no warning period and no inactivity period.
	WarningPeriod  Days         // Days before password expires during which the user is warned. -1 and 0 mean that there is no warning period.
	InactiveDays   Days         // Days after the password expires during which the user can still log in. -1 means there is no enforcement of an inactivity period.
	ExpirationDate time.Time    // The date of expiration of the account. Zero value means that the account will never expire.
	Reserved       interface{}  // Reserved for future use by the linux standard.
}

// NewShadowInfo parses a line in a format of /etc/shadow file and returns it as a ShadowInfo.
func NewShadowInfo(line string) (ShadowInfo, error) {
	fields := strings.Split(line, ":")

	if len(fields) != 9 {
		return ShadowInfo{}, fmt.Errorf("unexpected number of fields in shadow line %q", line)
	}

	ret := ShadowInfo{}
	var err error

	ret.Username = fields[0]
	ret.PasswordHash = PasswordHash(fields[1])

	ret.LastChangeDate, err = parseDate(fields[2])
	if err != nil {
		return ShadowInfo{}, err
	}

	ret.MinimumAge, err = NewDays(fields[3])
	if err != nil {
		return ShadowInfo{}, err
	}

	ret.MaximumAge, err = NewDays(fields[4])
	if err != nil {
		return ShadowInfo{}, err
	}

	ret.WarningPeriod, err = NewDays(fields[5])
	if err != nil {
		return ShadowInfo{}, err
	}

	ret.InactiveDays, err = NewDays(fields[6])
	if err != nil {
		return ShadowInfo{}, err
	}

	ret.ExpirationDate, err = parseDate(fields[7])
	if err != nil {
		return ShadowInfo{}, err
	}

	return ret, nil
}

// User represents data from /etc/passwd and /etc/shadow.
type User struct {
	Username     string       // Just a username.
	PasswordHash PasswordHash // Password field from /etc/passwd, contains 'x' if shadow file is used.
	UID          int          // Id of an user.
	GID          int          // Group id of an user.
	Comment      string       // Comment or a full name.
	Home         string       // Home directory.
	Shell        string       // User command interpreter.
}

// NewUser parses a line in the format of /etc/passwd and returns it as a User.
// It returns error if line format or some of the fields are invalid.
func NewUser(line string) (User, error) {
	fields := strings.Split(line, ":")

	if len(fields) != 7 {
		return User{}, fmt.Errorf("unexpected number of fields in passwd line %q", line)
	}

	var err error
	user := User{}

	user.Username = fields[0]
	user.PasswordHash = PasswordHash(fields[1])

	user.UID, err = strconv.Atoi(fields[2])
	if err != nil {
		return User{}, fmt.Errorf("UID should be a number, passwd line %q", line)
	}

	user.GID, err = strconv.Atoi(fields[3])
	if err != nil {
		return User{}, fmt.Errorf("GID should be a number, passwd line %q", line)
	}

	user.Comment = fields[4]
	user.Home = fields[5]
	user.Shell = fields[6]

	return user, nil
}

// UsesShadowFile checks if user's password is stored in /etc/shadow file.
func (u User) UsesShadowFile() bool {
	return u.PasswordHash == "x"
}

// IsBackdooredRoot checks if the username is not root, but uid is equal to 0.
func (u User) IsBackdooredRoot() bool {
	return u.UID == 0 && u.Username != "root"
}

// parseDate returns time.Date given string containing number of days since Jan 1, 1970,
// or zero value of time.Time if the string is empty.
func parseDate(date string) (time.Time, error) {
	if date == "" {
		return time.Time{}, nil
	}

	days, err := strconv.Atoi(date)
	if err != nil {
		return time.Time{}, err
	}

	return time.Date(1970, 0, 0, 0, 0, 0, 0, time.UTC).AddDate(0, 0, days), nil
}
