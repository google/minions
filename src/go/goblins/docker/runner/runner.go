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

// Package main contains a runner for the docker goblin.
package main

import (
	"flag"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/google/minions/go/goblins"
	"github.com/google/minions/go/goblins/docker"
	mpb "github.com/google/minions/proto/minions"
	pb "github.com/google/minions/proto/overlord"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

var (
	overlordAddr  = flag.String("overlord_addr", "127.0.0.1:10000", "Overlord address in the format of host:port")
	dockerPath    = flag.String("docker_path", "/var/lib/docker", "Docker directory")
	dockerVersion = flag.Int("docker_version", 2, "Version of Docker - 1 or 2")
	containerID   = flag.String("container_id", "", "ID of the Docker container to scan")
	driver        = flag.String("storage_driver", "overlay2", "Storage driver to use: aufs, overlay, overlay2")
)

func startScan(client pb.OverlordClient, mountPath string) []*mpb.Finding {
	log.Printf("Connecting to server")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	response, err := client.CreateScan(ctx, &pb.CreateScanRequest{})
	if err != nil {
		log.Fatalf("%v.CreateScan(_) = _, %v", client, err)
	}
	scanID := response.GetScanId()
	log.Printf("Created scan %s", scanID)
	log.Printf("Will now send files for each interests, a bit at a time")

	results, err := goblins.SendFiles(client, scanID, response.GetInterests(), mountPath)
	if err != nil {
		log.Fatalf("Failed sending files to the overlord: %v", err)
	}
	return results
}

func main() {
	flag.Parse()
	// TODO: check flags validity

	// Create a temp dir to mount image/container in.
	mountPath, err := ioutil.TempDir("", "DOCKER_MINION")
	log.Printf("Will mount on %s", mountPath)
	if err != nil {
		log.Fatal(err)
	}

	// TODO: double check this removeall, but should probably make sure we don't have weird symlinks/dir is empty
	defer os.RemoveAll(mountPath) // clean up dcker mount point.

	// Now mount the container.
	err = docker.Mount(mountPath, *dockerPath, *dockerVersion, *containerID, *driver)
	if err != nil {
		log.Fatalf("Failed to mount the docker container: %v", err)
	}
	defer docker.Umount(mountPath)

	conn, err := grpc.Dial(*overlordAddr, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("fail to connect to the overlord: %v", err)
	}
	defer conn.Close()
	client := pb.NewOverlordClient(conn)

	results := startScan(client, mountPath)

	if len(results) == 0 {
		log.Println("Scan completed but got no vulnerabilities back. Good! Maybe.")
		return
	}

	log.Println("Scan finished - we've got some results!")
	log.Println(goblins.HumanReadableDebug(results))
}
