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

package minions

import (
	"flag"
	"fmt"
	"log"
	"net"

	pb "github.com/google/minions/proto/minions"
	"google.golang.org/grpc"
)

var (
	port = flag.Int("port", 20001, "Port to bind the minion to")
)

// StartMinion initializes a gRPC endpoint and populates it with the provided Minion.
// It can be used by minions to easily start themselves up.
func StartMinion(minion Minion, minionName string) {
	flag.Parse()
	log.Printf("StartMinion: Starting up minion on localhost: %s", minionName)
	// TODO(paradoxengine): support binding on arbitrary IPs
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *port))
	if err != nil {
		log.Fatalf("StartMinion: Failed to bind Minion to port: %v", err)
	}
	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)
	pb.RegisterMinionServer(grpcServer, minion)
	log.Printf("StartMinion: Minion created and registered, entering busy loop, ready to scan.")
	grpcServer.Serve(lis)
}
