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

	"github.com/google/minions/go/grpcutil"
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
	sslCert = flag.String("ssl_cert", "", "Path to the SSL certificate (crt)")
	sslKey  = flag.String("ssl_key", "", "Path to the SSL key (key)")
	caCert  = flag.String("ca_cert", "", "Path to the Certificate Authority certificate used to validate Minions certificates")
)

func newServer() (*overlord.Server, error) {
	ctx := context.Background()
	return overlord.New(ctx, minions, *caCert)
}

func main() {
	flag.Var(&minions, "minions", "Addresses of minions to boot against")

	flag.Parse()
	fmt.Printf("Starting up overlord server. Got these minion addresses: %s \n", minions)
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	creds, err := grpcutil.GetSslServerCreds(*sslCert, *sslKey, "") // We don't validate client certs.
	if err != nil {
		log.Fatalf("Failed to retrieve SSL creds: %v", err)
	}
	if creds == nil {
		log.Println("WARNING: starting the Overlord with no SSL support")
	} else {
		opts = append(opts, creds)
	}
	grpcServer := grpc.NewServer(opts...)
	s, err := newServer()
	if err != nil {
		log.Fatalf("failed to build server: %v", err)
	}
	pb.RegisterOverlordServer(grpcServer, s)
	fmt.Println("Server created and registered, entering busy loop!")
	grpcServer.Serve(lis)
}
