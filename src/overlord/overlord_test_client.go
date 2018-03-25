package main

import (
	"flag"
	"log"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	pb "github.com/paradoxengine/minions/proto/overlord"
)

var (
	serverAddr = flag.String("server_addr", "127.0.0.1:10000", "The server address in the format of host:port")
)

func startScan(client pb.OverlordClient) {
	log.Printf("Connecting to server")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	response, err := client.Scan(ctx, &pb.ScanRequest{})
	if err != nil {
		log.Fatalf("%v.Scan(_) = _, %v", client, err)
	}
	log.Printf("Received response: %s", response)
}

func main() {
	flag.Parse()
	conn, err := grpc.Dial(*serverAddr, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("fail to dial: %v", err)
	}
	defer conn.Close()
	client := pb.NewOverlordClient(conn)

	startScan(client)
}
