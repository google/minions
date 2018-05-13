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

package overlord

import (
	pb "github.com/google/minions/proto/overlord"
	"golang.org/x/net/context"
)

type Overlord struct {
}

func (s *Overlord) Scan(ctx context.Context, req *pb.ScanRequest) (*pb.ScanResponse, error) {
	return &pb.ScanResponse{"foo"}, nil
}
