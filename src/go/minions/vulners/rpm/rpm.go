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
Package rpm reads package information through RPMlib from a Packages database.

The Packages file is, usually, in the Berkeley DB format (and reading it natively
without rpmlib is an uphill battle) but the RPM libraries will abstract that need.

Note that this package expects the rpmlib dev library to be installed on the
system at compile time, as it uses cgo to leverage the C API bindings.
*/
package rpm

import (
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/necomeshi/rpmlib"
)

// Package represents information about a package.
type Package struct {
	Name         string
	Version      string
	Architecture string
}

// ReadDb reads one Entry (package info) from s.
// A successful call returns err == nil. It returns io.EOF as error when
// the scanner has reached end of file.
// Important note: keys in returned Entry are lowercase.
func ReadDb(db *os.File) ([]Package, error) {
	// Verify the file name is Packages (hard-coded in RPMlib)
	fname := filepath.Base(db.Name())
	if fname != "Packages" {
		return nil, errors.New("Filename must be Packages, not " + fname)
	}

	// Obtain containing directory, which needs to be containing exactly one file called Packages.
	dbpath := filepath.Dir(db.Name())
	return getPackages(dbpath)
}

func getPackages(dbpath string) ([]Package, error) {
	rpmlib.SetDbPath(dbpath)
	ts, err := rpmlib.NewTransactionSet()
	if err != nil {
		return nil, err
	}
	defer ts.Free()

	iter, err := ts.SequencialIterator()
	if err != nil {
		return nil, err
	}
	defer iter.Free()

	pkgs := make([]Package, 1)
	for {
		h, itrErr := iter.Next()
		defer h.Free()

		if itrErr == io.EOF {
			break
		}

		if itrErr != nil {
			return nil, itrErr
		}

		name, _ := h.GetString(rpmlib.RPMTAG_NAME)
		version, _ := h.GetString(rpmlib.RPMTAG_VERSION)
		arch, _ := h.GetString(rpmlib.RPMTAG_ARCH)

		// gpg-pubkey is a well-known magical package, so we skip it.
		if name == "gpg-pubkey" {
			continue
		}

		if name == "" || version == "" || arch == "" {
			log.Printf("Missing name, version or arch. Skipping.[%s - %s - %s]\n", name, version, arch)
			continue
		}

		pkgs = append(pkgs, Package{name, version, arch})
	}
	return pkgs, nil
}
