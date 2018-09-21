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
	"fmt"
	"regexp"

	mpb "github.com/google/minions/proto/minions"
	opb "github.com/google/minions/proto/overlord"
)

// Minify returns a slice of Interest that matches the same set of files
// as the original slice, but possibly using less Interests. For now
// does simple deduplication between interests.
func Minify(interests []*mpb.Interest) []*mpb.Interest {
	uniqueInterests := make(map[string]*mpb.Interest)

	for _, i := range interests {
		// First of all, add the unique paths.
		if _, hasPathRegexp := uniqueInterests[i.PathRegexp]; !hasPathRegexp {
			uniqueInterests[i.PathRegexp] = i
			continue
		}

		// Overwrite existing Interest if a new one is METADATA_AND_DATA,
		// as it requires "more" information than just one or the other.
		if i.DataType == mpb.Interest_METADATA_AND_DATA {
			uniqueInterests[i.PathRegexp] = i
		}
	}

	// Map to interests.
	var ret []*mpb.Interest
	for _, v := range uniqueInterests {
		ret = append(ret, v)
	}

	return ret
}

// IsMatching checks if the File is matching the Interest.
// Error is returned where the PathRegexp in the Interest is malformed or there is no
// metadata.
func IsMatching(interest *mpb.Interest, file *opb.File) (bool, error) {
	if file.GetMetadata() == nil {
		return false, fmt.Errorf("cannot match file without metadata")
	}
	// If the path doesn't match or the matching returns an error.
	if match, err := regexp.MatchString(interest.PathRegexp, file.GetMetadata().Path); err != nil || !match {
		return false, err
	}

	dataNeededAndThere := (interest.DataType == mpb.Interest_METADATA_AND_DATA && len(file.GetDataChunks()) > 0)
	return interest.DataType == mpb.Interest_METADATA || dataNeededAndThere, nil
}
