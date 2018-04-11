package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/paradoxengine/minions/src/overlord"

	"google.golang.org/grpc"

	pb "github.com/paradoxengine/minions/proto/overlord"
)

var (
	port = flag.Int("port", 10000, "Overlord server port")
)

func newServer() *overlord.Overlord {
	s := &overlord.Overlord{}
	return s
}

func main() {
	flag.Parse()
	fmt.Println("Starting up overlord server")
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)
	pb.RegisterOverlordServer(grpcServer, newServer())
	grpcServer.Serve(lis)
}
