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

package interests

import (
	"errors"
	"testing"

	mpb "github.com/google/minions/proto/minions"
	opb "github.com/google/minions/proto/overlord"
	"github.com/stretchr/testify/require"
)

func TestMinifyOnSamePathKeepsMetadataAndData(t *testing.T) {
	i1 := &mpb.Interest{
		DataType:   mpb.Interest_METADATA_AND_DATA,
		PathRegexp: "/some/regexp",
	}
	i2 := &mpb.Interest{
		DataType:   mpb.Interest_METADATA,
		PathRegexp: "/some/regexp",
	}
	interests := []*mpb.Interest{i1, i2}
	minified := Minify(interests)
	require.Len(t, minified, 1)
	require.Equal(t, minified[0], i1)
}

func TestMinifyOnDifferentPathDoesNotDedupe(t *testing.T) {
	i1 := &mpb.Interest{
		DataType:   mpb.Interest_METADATA_AND_DATA,
		PathRegexp: "/some/regexp",
	}
	i2 := &mpb.Interest{
		DataType:   mpb.Interest_METADATA_AND_DATA,
		PathRegexp: "/some/regexp2",
	}
	interests := []*mpb.Interest{i1, i2}
	minified := Minify(interests)
	require.Contains(t, minified, i1)
	require.Contains(t, minified, i2)
}

var isMatchingV = []struct {
	title string
	i     *mpb.Interest
	f     *opb.File
	e     error
	r     bool
}{
	{
		"empty_interest_file",
		&mpb.Interest{},
		&opb.File{},
		errors.New(""),
		false,
	},
	{
		"no_file_metadata",
		&mpb.Interest{
			DataType:   mpb.Interest_METADATA_AND_DATA,
			PathRegexp: "/",
		},
		&opb.File{},
		errors.New(""),
		false,
	},
	{
		"brokenpath",
		&mpb.Interest{
			DataType:   mpb.Interest_METADATA_AND_DATA,
			PathRegexp: "[a-z{}",
		},
		&opb.File{
			Metadata: &mpb.FileMetadata{
				Path: "/foobar",
			},
		},
		errors.New(""),
		false,
	},
	{
		"path_matches_metadata",
		&mpb.Interest{
			DataType:   mpb.Interest_METADATA,
			PathRegexp: "/foobar",
		},
		&opb.File{
			Metadata: &mpb.FileMetadata{
				Path: "/foobar",
			},
		},
		nil,
		true},
	{
		"path_matches_metadata_data",
		&mpb.Interest{
			DataType:   mpb.Interest_METADATA_AND_DATA,
			PathRegexp: "/foobar",
		},
		&opb.File{
			Metadata: &mpb.FileMetadata{
				Path: "/foobar",
			},
			DataChunks: []*opb.DataChunk{&opb.DataChunk{}},
		},
		nil,
		true,
	},
	{
		"does_not_match",
		&mpb.Interest{
			DataType:   mpb.Interest_METADATA_AND_DATA,
			PathRegexp: "/somethingelse",
		},
		&opb.File{
			Metadata: &mpb.FileMetadata{
				Path: "/foobar",
			},
			DataChunks: []*opb.DataChunk{&opb.DataChunk{}},
		},
		nil,
		false,
	},
	{
		"does_not_match_on_no_data",
		&mpb.Interest{
			DataType:   mpb.Interest_METADATA_AND_DATA,
			PathRegexp: "/foobar",
		}, &opb.File{
			Metadata: &mpb.FileMetadata{
				Path: "/foobar",
			},
		},
		nil,
		false,
	},
}

func TestIsMatching(t *testing.T) {
	for _, tt := range isMatchingV {
		t.Run(tt.title, func(t *testing.T) {
			res, err := IsMatching(tt.i, tt.f)
			if tt.e != nil {
				if err == nil {
					t.Errorf("Wanted error, got nothing")
				}
				return
			}
			if err != nil {
				t.Errorf("Wanted no error, got: %v", err)
			}
			if res != tt.r {
				t.Errorf("Wanted %t, got %t", tt.r, res)
			}
		})
	}
}
