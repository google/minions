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

// Package docker contains libraries to access and handle docker containers.
// This feature will *only* work on Linux OS with appropriate Kernel support.
package docker

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const aufsPath = "/sbin/mount.aufs"

// Mount mounts the container's filesystem into a mount directory.
// Note that this method just executes a bunch of shell command
// to build the filesystem. Not much magic here.
// All of this is based on https://github.com/google/docker-explorer/blob/master/docker_explorer/lib/storage.py
func Mount(mountDir string, dockerDir string, dockerVersion int, containerID string, driver string) error {
	var err error
	var commands []*exec.Cmd

	//TODO: figure out the volume and mountpoints for AUFS

	rootDir := filepath.Clean(filepath.Join(dockerDir, "..."))
	mountID := "" // Default with V1
	if dockerVersion == 2 {
		cPath := filepath.Join(dockerDir, "image", driver, "layerdb", "mounts", containerID)
		mid, err := ioutil.ReadFile(filepath.Join(cPath, "mount-id"))
		if err != nil {
			return err
		}
		mountID = string(mid)
	}

	switch driver {
	case "aufs":
		commands, err = aufsMountCommands(mountDir, rootDir, mountID, dockerDir, driver, dockerVersion, nil, nil)
	case "overlay":
		commands, err = overlayFsMountCommands(mountDir, mountID, dockerDir, driver, dockerVersion)
	case "overlay2":
		commands, err = overlayFsMountCommands(mountDir, mountID, dockerDir, driver, dockerVersion)
	default:
		return errors.New("unknown driver")
	}
	if err != nil {
		return err
	}

	for _, c := range commands {
		fmt.Printf("Will now run the following command: %s ", c.Path)
		for _, a := range c.Args {
			fmt.Printf(" %s ", a)
		}
		fmt.Print("\n")
		stdoutStderr, err := c.CombinedOutput()
		fmt.Printf("%s\n", stdoutStderr)
		if err != nil {
			log.Fatal(err)
		}
	}
	return nil
}

type storageInfo struct {
	source      string
	destination string
	name        string
}

func aufsMountCommands(mountDir string, rootDir string, mountID string, dockerDir string,
	storageMethod string, dockerVersion int, volumes map[string]string, mountPoints []storageInfo) ([]*exec.Cmd, error) {

	if _, err := os.Stat(aufsPath); os.IsNotExist(err) {
		return nil, errors.New("cannot find /sbin/mount.aufs. Maybe install aufs-tools?")
	}
	layersPath := filepath.Join(dockerDir, storageMethod, "layers", mountID)
	containerID := filepath.Join(dockerDir, storageMethod, "diff", mountID)
	if dockerVersion == 1 { // Old-style layers path.
		layersPath = filepath.Join(dockerDir, storageMethod, "layers", containerID)
	}

	var commands []*exec.Cmd
	mountpointPath := filepath.Join(dockerDir, storageMethod, "diff", containerID)
	// Mount the base.
	opts := fmt.Sprintf("-oro,br%s=ro+wh", mountpointPath)
	args := []string{"-taufs", opts, "none", mountDir}
	commands = append(commands, exec.Command("mount", args...))
	// Now mount all layers above.
	files, err := ioutil.ReadDir(layersPath)
	if err != nil {
		return nil, fmt.Errorf("Error while building layers mount command: %v", err)
	}
	for _, f := range files {
		path := filepath.Join(dockerDir, storageMethod, "diff", f.Name())
		opts := fmt.Sprintf("-oro,remount,append:%s=ro+wh", path)
		args := []string{"-taufs", opts, "none", mountDir}
		commands = append(commands, exec.Command("mount", args...))
	}

	// Now mount volumes.
	switch dockerVersion {
	case 1:
		return append(commands, mountVolumesDocker1(mountDir, rootDir, volumes)...), nil
	case 2:
		return append(commands, mountVolumesDocker2(mountDir, mountPoints)...), nil
	default:
		return nil, fmt.Errorf("Unsupported docker version: %d", dockerVersion)
	}
}

func mountVolumesDocker1(mountDir string, rootDir string, volumes map[string]string) []*exec.Cmd {
	commands := make([]*exec.Cmd, 0)
	for mountpoint, storage := range volumes {
		storageIhp := strings.TrimLeft(mountpoint, string(os.PathSeparator))
		mountpointIhp := strings.TrimLeft(storage, string(os.PathSeparator))
		storagePath := filepath.Join(rootDir, storageIhp)
		volumeMountpoint := filepath.Join(mountDir, mountpointIhp)
		args := []string{"--bind", "-oro", storagePath, volumeMountpoint}
		commands = append(commands, exec.Command("mount", args...))
	}
	return commands
}

func mountVolumesDocker2(mountDir string, mountPoints []storageInfo) []*exec.Cmd {
	commands := make([]*exec.Cmd, 0)
	for _, s := range mountPoints {
		srcMount := strings.TrimLeft(s.source, string(os.PathSeparator))
		dstMount := strings.TrimLeft(s.destination, string(os.PathSeparator))
		if srcMount == "" {
			volumeName := s.name
			srcMount = filepath.Join("docker", "volumes", volumeName, "_data")
		}
		storagePath := filepath.Join(mountDir, dstMount)
		volumeMountpoint := filepath.Join(mountDir, dstMount)
		args := []string{"--bind", "-oro", storagePath, volumeMountpoint}
		commands = append(commands, exec.Command("mount", args...))
	}
	return commands
}

func overlayFsMountCommands(mountDir string, mountID string, dockerDir string,
	storageMethod string, dockerVersion int) ([]*exec.Cmd, error) {
	mountIDPath := filepath.Join(dockerDir, storageMethod, mountID)
	const lowerdirName = "lower"
	const upperdirName = "diff"

	lowerDirPath := filepath.Join(mountIDPath, lowerdirName)
	lowerContent, err := ioutil.ReadFile(lowerDirPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read lower content pointer: %s", err)
	}

	// There are differences between overlay and overlay2 here for the lower directory
	if storageMethod == "overlay" {
		lowerDirPath = filepath.Join(dockerDir, storageMethod, string(lowerContent), "root")
	} else {
		// For the overlay2 driver, the pointer to the 'lower directory' can be
		// made of multiple layers.
		// For that argument to be passed to the mount.overlay command, we need to
		// reconstruct full paths to all these layers.
		// ie: from 'abcd:0123' to '/var/lib/docker/abcd:/var/lib/docker/0123'
		var paths []string
		for _, lc := range strings.Split(string(lowerContent), ":") {
			paths = append(paths, filepath.Join(dockerDir, storageMethod, lc))
		}
		lowerDirPath = strings.Join(paths, ":")
	}
	upperDirPath := filepath.Join(mountIDPath, upperdirName)

	opts := fmt.Sprintf(`-oro,lowerdir=%s:%s`, upperDirPath, lowerDirPath)
	args := []string{"-toverlay", opts, "overlay", mountDir}
	command := exec.Command("mount", args...)
	return []*exec.Cmd{command}, nil
}
