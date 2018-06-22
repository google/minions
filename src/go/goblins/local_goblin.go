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
	"log"
	"time"

	pb "github.com/google/minions/proto/overlord"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

var (
	overlordAddr = flag.String("overlord_addr", "127.0.0.1:10000", "Overlord address in the format of host:port")
)

func startScan(client pb.OverlordClient) {
	log.Printf("Connecting to server")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	response, err := client.CreateScan(ctx, &pb.CreateScanRequest{})
	if err != nil {
		log.Fatalf("%v.Scan(_) = _, %v", client, err)
	}
	log.Printf("Received response: %s", response)

	log.Printf("Will now send the following files.")
	for _, i := range response.GetInterests() {
		log.Printf(i.GetPathRegexp())
	}
}

func main() {
	flag.Parse()
	conn, err := grpc.Dial(*overlordAddr, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("fail to dial: %v", err)
	}
	defer conn.Close()
	client := pb.NewOverlordClient(conn)

	startScan(client)
}
