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
	"io/ioutil"
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

// ReadDb reads the entire package repository from a Packages RPM DB.
// An important, non trivial side effect is that the RPM libraries will
// create a whole array of indexes and ancillary files upon reading the DB.
// These files will NOT be cleaned up by this function, and it's best to copy
// the file in a temporary directory. There migthe be some API wizardry to
// avoid it, but until I figure it out you can use ReadDbAndCleanup.
// ReadDb will close the file it's handled.
func ReadDb(db *os.File) ([]Package, error) {
	// Verify the file name is Packages (hard-coded in RPMlib)
	fname := filepath.Base(db.Name())
	if fname != "Packages" {
		return nil, errors.New("Filename must be Packages, not " + fname)
	}

	// Obtain containing directory, which needs to be containing exactly one file called Packages.
	dbpath := filepath.Dir(db.Name())
	pkgs, err := getPackages(dbpath)
	db.Close()
	return pkgs, err
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

	pkgs := make([]Package, 0)
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

// ReadDbAndCleanup will link the db to a temporary so that the additional
// files created will be deleted once done. As link won't work everywhere, if that
// fails we'll copy the file instead, which is an important performance tax.
func ReadDbAndCleanup(db *os.File) ([]Package, error) {
	// Create temp directory where we'll copy the DB
	dir, err := ioutil.TempDir("", "minionsrpm")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	// Try to link, and if it fails copy instead.
	tempPath := dir + "/Packages"

	// now either link or copy the file to a temp dir.
	linkErr := os.Link(db.Name(), tempPath)
	var f *os.File
	if linkErr != nil {
		// Link failed for whatever reason, let's copy instead.
		f, err = os.Create(tempPath)
		if err != nil {
			return nil, err
		}
		if _, err = io.Copy(f, db); err != nil {
			return nil, err
		}
		// Force sync
		err = f.Sync()
		if err != nil {
			return nil, err
		}
	} else {
		f, err = os.Open(tempPath)
	}

	// Now send through ReadDb.
	if err != nil {
		return nil, err
	}
	return ReadDb(f)
}
