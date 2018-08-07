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

package tomcat

import (
	"context"
	"testing"

	"github.com/golang/protobuf/proto"
	pb "github.com/google/minions/proto/minions"
	"github.com/stretchr/testify/require"
)

func TestInitialInterests(t *testing.T) {
	ctx := context.Background()
	minion := &Minion{}
	want := &pb.ListInitialInterestsResponse{
		Interests: []*pb.Interest{
			&pb.Interest{
				PathRegexp: `/conf/server\.xml$`,
				DataType:   pb.Interest_METADATA_AND_DATA,
			},
		},
	}
	have, err := minion.ListInitialInterests(ctx, &pb.ListInitialInterestsRequest{})
	require.NoError(t, err)
	if !proto.Equal(have, want) {
		t.Errorf("ListInitialInterests = %v, want %v", have, want)
	}
}

// TestAdditionalInterests checks, whether outputs that are supposed to return
// new Interests do so and if the errors are correctly returned from the
// AnalyzeFiles method.
func TestAdditionalInterestsAndErrors(t *testing.T) {
	ctx := context.Background()
	minion := &Minion{}

	testCases := []struct {
		in   []*pb.File
		err  bool
		want *pb.AnalyzeFilesResponse
	}{
		{
			in: []*pb.File{
				&pb.File{
					Metadata: &pb.FileMetadata{
						Path: "/something/something/conf/server.xml",
					},
					Data: []byte("<Server><Service><Engine><Host appBase=\"one\" /><Host appBase=\"two\" /></Engine></Service></Server>"),
				},
			},
			err: false,
			want: &pb.AnalyzeFilesResponse{
				NewInterests: []*pb.Interest{
					&pb.Interest{
						PathRegexp: `one/(?:host-)?manager/WEB-INF/web\.xml$`,
						DataType:   pb.Interest_METADATA,
					},
					&pb.Interest{
						PathRegexp: `two/(?:host-)?manager/WEB-INF/web\.xml$`,
						DataType:   pb.Interest_METADATA,
					},
				},
			},
		},
		{
			in: []*pb.File{
				&pb.File{
					Metadata: &pb.FileMetadata{
						Path: "/tomcat/something/manager/WEB-INF/web.xml",
					},
				},
			},
			err: false,
			want: &pb.AnalyzeFilesResponse{
				NewInterests: []*pb.Interest{
					&pb.Interest{
						PathRegexp: `/tomcat/conf/tomcat-users\.xml$`,
						DataType:   pb.Interest_METADATA_AND_DATA,
					},
				},
			},
		},
		{
			in: []*pb.File{
				&pb.File{
					Metadata: &pb.FileMetadata{
						Path: "/tomcat2/something/host-manager/WEB-INF/web.xml",
					},
				},
			},
			err: false,
			want: &pb.AnalyzeFilesResponse{
				NewInterests: []*pb.Interest{
					&pb.Interest{
						PathRegexp: `/tomcat2/conf/tomcat-users\.xml$`,
						DataType:   pb.Interest_METADATA_AND_DATA,
					},
				},
			},
		},
		{
			in: []*pb.File{
				&pb.File{
					Metadata: &pb.FileMetadata{
						Path: "/boring_file.asdf",
					},
				},
			},
			err:  false,
			want: &pb.AnalyzeFilesResponse{},
		},

		{
			// Lack of metadata.
			in: []*pb.File{
				&pb.File{},
			},
			err: true,
		},
		{
			// Incorrect server.xml.
			in: []*pb.File{
				&pb.File{
					Metadata: &pb.FileMetadata{
						Path: "/conf/server.xml",
					},
					Data: []byte("<tag>"),
				},
			},
			err: true,
		},
		{
			//Incorrect tomcat-users.xml.
			in: []*pb.File{
				&pb.File{
					Metadata: &pb.FileMetadata{
						Path: "/conf/tomcat-users.xml",
					},
					Data: []byte("<tag>"),
				},
			},
			err: true,
		},
	}

	for _, tt := range testCases {
		have, err := minion.AnalyzeFiles(ctx, &pb.AnalyzeFilesRequest{
			Files: tt.in,
		})
		if tt.err && err == nil {
			t.Errorf("AnalyzeFiles(%v) should return an error", tt.in)
			continue
		}
		if !tt.err && err != nil {
			t.Errorf("AnalyzeFiles(%v): got an error %v, want %v", tt.in, err, tt.want)
			continue
		}
		if err == nil && !proto.Equal(have, tt.want) {
			t.Errorf("AnalyzeFiles(%v) = %v, want %v", tt.in, have, tt.want)
		}
	}
}

func TestReturningFindings(t *testing.T) {
	ctx := context.Background()
	minion := &Minion{}

	testCase := &pb.AnalyzeFilesRequest{
		Files: []*pb.File{
			&pb.File{
				Metadata: &pb.FileMetadata{
					Path: "/something/conf/tomcat-users.xml",
				},
				Data: []byte("<tomcat-users><user username=\"admin\" password=\"admin\" roles=\"manager-gui\"/><user username=\"tomcat\" password=\"tomcat\" roles=\"manager-jmx\"/></tomcat-users>"),
			},
		},
	}

	have, err := minion.AnalyzeFiles(ctx, testCase)
	require.NoError(t, err)
	require.Len(t, have.GetFindings(), 2)

	for _, f := range have.GetFindings() {
		if want := "tomcat_weak_manager_credentials"; f.GetAdvisory().Reference != want {
			t.Errorf("Expected Advisory with reference %q, got %v instead.", want, f.Advisory)
		}
	}
}
