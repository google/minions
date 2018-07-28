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

package rpm

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVulnerablePackages(t *testing.T) {
	basepath, err := os.Getwd()
	pkgs, err := ReadDbAndCleanup(basepath + "/testdata/vulnerable/Packages")
	assert.NoError(t, err)
	assert.Equal(t, "pass", pkgs[0].Name)
	assert.Equal(t, "1.7.1", pkgs[0].Version)
	assert.Equal(t, "noarch", pkgs[0].Architecture)
}

func TestEmptyPackages(t *testing.T) {
	basepath, err := os.Getwd()
	pkgs, err := ReadDbAndCleanup(basepath + "/testdata/empty/Packages")
	assert.NoError(t, err)
	assert.Empty(t, pkgs)
}
