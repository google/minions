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

package vulners

import (
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildsVersion(t *testing.T) {

	type Result struct {
		Os  string
		Ver string
	}

	res := map[int]Result{
		1: Result{Os: "Ubuntu", Ver: "18.04"},
		2: Result{Os: "CoreOS", Ver: "835.9.0"},
	}

	for test := 1; test <= len(res); test++ {
		basepath, err := os.Getwd()
		filename := basepath + "/testdata/os-release." + strconv.Itoa(test) + ".txt"
		f, err := os.Open(filename)
		os, ver, err := getOsAndversion(f)
		if err != nil {
			t.Fatalf("Could not process test '%v': %v", filename, err)
		}
		assert.Equal(t, res[test].Os, os, "Mismatching parsed os, got %s expected %s", os, res[test].Os)
		assert.Equal(t, res[test].Ver, ver, "Mismatching parsed version, got %s expected %s", ver, res[test].Ver)
	}
}
