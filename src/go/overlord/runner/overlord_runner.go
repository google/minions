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

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"strings"

	"golang.org/x/net/context"

	"github.com/google/minions/go/overlord"
	pb "github.com/google/minions/proto/overlord"
	"google.golang.org/grpc"
)

type flagStrings []string

func (f *flagStrings) String() string {
	return fmt.Sprint(strings.Join(*f, ""))
}

func (f *flagStrings) Set(value string) error {
	*f = append(*f, value)
	return nil
}

var (
	minions flagStrings
	port    = flag.Int("port", 10000, "Overlord server port")
)

func newServer() (*overlord.Server, error) {
	ctx := context.Background()
	// TODO(paradoxengine): Once TLS auth is impelemneted everywhere, remove the insecure flag.
	return overlord.New(ctx, minions, grpc.WithInsecure())
}

func main() {
	flag.Var(&minions, "", "Addresses of minions to boot against")

	flag.Parse()
	fmt.Println("Starting up overlord server")
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)
	s, err := newServer()
	if err != nil {
		log.Fatalf("failed to build server: %v", err)
	}
	pb.RegisterOverlordServer(grpcServer, s)
	fmt.Println("Server created and registered, entering busy loop!")
	grpcServer.Serve(lis)
}
