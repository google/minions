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
	"testing"

	mpb "github.com/google/minions/proto/minions"
	pb "github.com/google/minions/proto/overlord"
	"github.com/stretchr/testify/require"
)

func Test_LocalStateManager_createsScan(t *testing.T) {
	l := NewLocalStateManager()
	require.False(t, l.ScanExists("foo_scan"))
	l.CreateScan("foo_scan")
	require.True(t, l.ScanExists("foo_scan"))
}

func Test_LocalStateManager_storesAndRetrievesFiles(t *testing.T) {
	l := NewLocalStateManager()
	l.CreateScan("a")
	files := make([]*pb.File, 0)
	files = append(files, emptyFile("/foo"))
	l.AddFiles("a", files)
	retrievedFiles, err := l.GetFiles("a")
	require.NoError(t, err)
	require.ElementsMatch(t, files, retrievedFiles)

	files = append(files, emptyFile("/bar"))
	l.AddFiles("a", files)
	retrievedFiles, err = l.GetFiles("a")
	require.NoError(t, err)
	require.ElementsMatch(t, files, retrievedFiles)
}

func Test_LocalStateManager_deletesFiles(t *testing.T) {
	l := NewLocalStateManager()
	scanID := "irrelevant"
	l.CreateScan(scanID)
	files := make([]*pb.File, 0)
	files = append(files, emptyFile("/foo"))
	files = append(files, emptyFile("/bar"))
	l.AddFiles(scanID, files)
	retrievedFiles, err := l.GetFiles(scanID)
	require.NoError(t, err)
	require.ElementsMatch(t, files, retrievedFiles)

	// Now remove file and check the remaining one.
	ok, err := l.RemoveFile(scanID, emptyFile("/foo"))
	require.True(t, ok)
	retrievedFiles, err = l.GetFiles(scanID)
	require.NoError(t, err)
	require.Len(t, retrievedFiles, 1)
	// Just /bar left
	require.Equal(t, "/bar", retrievedFiles[0].GetMetadata().GetPath())
}

func emptyFile(path string) *pb.File {
	// Note the creation of the datachunks, which is a bit testing internals :(
	return &pb.File{Metadata: &mpb.FileMetadata{Path: path},
		DataChunks: []*pb.DataChunk{
			&pb.DataChunk{
				Offset: 0,
			},
		},
	}
}

func Test_LocalStateManager_storesAndRetrievesInterests(t *testing.T) {
	l := NewLocalStateManager()
	l.CreateScan("a")
	interest := &mpb.Interest{DataType: mpb.Interest_METADATA_AND_DATA, PathRegexp: "foo"}
	l.AddInterest("a", interest, "minion")
	retrievedInterests, err := l.GetInterests("a")
	require.NoError(t, err)
	require.Equal(t, interest, retrievedInterests[0].interest)

	interest2 := &mpb.Interest{DataType: mpb.Interest_METADATA_AND_DATA, PathRegexp: "foo2"}
	l.AddInterest("a", interest2, "minion2")
	retrievedInterests, err = l.GetInterests("a")
	expectedInterests := []*mpb.Interest{interest, interest2}
	actualInterests := make([]*mpb.Interest, 2)
	actualInterests[0] = retrievedInterests[0].interest
	actualInterests[1] = retrievedInterests[1].interest
	require.NoError(t, err)
	require.ElementsMatch(t, expectedInterests, actualInterests)
}

// TODO: test chunk rebuild
