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

package docker

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLocalTest(t *testing.T) {
	mountDir := "/tmp/foo"
	dockerDir := "/var/lib/docker"
	dockerVersion := 2
	containerID := "45ce89d200dd7a0e4aae5fd063471ecc0cbc2cf6b01a785bd4ff03d9c93afcdf"
	driver := "overlay2"
	err := Mount(mountDir, dockerDir, dockerVersion, containerID, driver)
	require.NoError(t, err)
	err = Umount(mountDir)
	require.NoError(t, err)
}
