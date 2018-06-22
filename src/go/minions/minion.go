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

/*
Package minion specifies a common Minion interface.

A minion performs certain checks on the files provided and returns issues
it finds to the caller. Each minion is interested in certain files that can
be discovered using ListInitialInterests method. A minion can also return
additional interests to the caller as a result of an AnalyzeFiles method call.
*/
package minions

import (
	pb "github.com/google/minions/proto/minions"
	"golang.org/x/net/context"
)

// Minion is a interface that should be implemented by every Minion.
type Minion interface {
	// ListInitialInterests returns the initial Interests of a Minion.
	ListInitialInterests(ctx context.Context, req *pb.ListInitialInterestsRequest) (*pb.ListInitialInterestsResponse, error)
	// AnalyzeFiles returns security issues found in files from AnalyzeFilesRequest.
	AnalyzeFiles(ctx context.Context, req *pb.AnalyzeFilesRequest) (*pb.AnalyzeFilesResponse, error)
}
