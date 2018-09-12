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

// Package goblins contains common code across Goblins
package goblins

import (
	"fmt"
	"strings"

	mpb "github.com/google/minions/proto/minions"
)

// HumanReadableDebug generates a human readable debug form from a slice
// of results.
func HumanReadableDebug(results []*mpb.Finding) string {
	var b strings.Builder
	for _, r := range results {
		b.WriteString("------------------------------")
		fmt.Fprintf(&b, "%s : %s\n",
			r.GetAdvisory().GetReference(), r.GetAdvisory().GetDescription())
		fmt.Fprintf(&b, "Detected by %s\n", r.GetSource().GetMinion())
		if len(r.GetVulnerableResources()) > 0 {
			res := r.GetVulnerableResources()[0]
			fmt.Fprintf(&b, "Resource: %s [%s]", res.GetPath(), res.GetAdditionalInfo())
		}
		fmt.Fprintf(&b, "Severity: %s\n", r.GetSeverity())
	}
	return b.String()
}
