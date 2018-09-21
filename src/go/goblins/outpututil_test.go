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

package goblins

import (
	"testing"

	mpb "github.com/google/minions/proto/minions"
	"github.com/stretchr/testify/require"
)

func TestHumanReadableDebugResultsOutput(t *testing.T) {
	f1 := &mpb.Finding{Advisory: &mpb.Advisory{Description: "foodesc"}}
	f2 := &mpb.Finding{Severity: mpb.Finding_SEVERITY_CRITICAL}
	findings := []*mpb.Finding{f1, f2}
	require.Contains(t, HumanReadableDebug(findings), "foodesc")
	require.Contains(t, HumanReadableDebug(findings), "CRITICAL")
}
func TestHumanReadableDebugEmptyOutput(t *testing.T) {
	require.Equal(t, "", HumanReadableDebug(make([]*mpb.Finding, 0)))
}
