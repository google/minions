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

package dpkg

import (
	"reflect"
	"strings"
	"testing"
)

var scanTests = []struct {
	Name   string
	Input  string
	Output Entry
	Error  bool
}{
	{
		Name: "correct entry",
		Input: "Package: packagename\n" +
			"Version: 1.0.0\n" +
			"Replaces: oldpackage\n" +
			"Description: The description\n" +
			" This is a test package.\n" +
			" .\n" +
			"\n",
		Output: Entry{
			"package":     "packagename",
			"version":     "1.0.0",
			"replaces":    "oldpackage",
			"description": "The description\n This is a test package.\n .",
		},
	},
	{
		Name: "newline description",
		Input: "Package: packagename\n" +
			"Foo:\n" +
			"      bar\n" +
			"\n",
		Output: Entry{
			"package": "packagename",
			"foo":     "bar",
		},
	},
	{
		Name: "multiple entries",
		Input: "Package: first\n" +
			"Version: 1.0.0\n" +
			"\n" +
			"Package: second\n" +
			"Version: 2.0.0\n" +
			"\n",
		Output: Entry{
			"package": "first",
			"version": "1.0.0",
		},
	},
	{
		Name: "missing empty line",
		Input: "Package: packagename\n" +
			"Version: 1.0.0\n",
		Error: true,
	},
	{
		Name: "incorrect key",
		Input: "Package: name\n" +
			"missing colon\n",
		Error: true,
	},
	{
		Name:  "missing newline after value",
		Input: "Package: name",
		Error: true,
	},
	{
		Name:  "empty stream",
		Input: "",
		Error: true,
	},
	{
		Name:  "missing value",
		Input: "Foo:",
		Error: true,
	},
}

func TestScan(t *testing.T) {
	for _, tt := range scanTests {
		s := NewScanner(strings.NewReader(tt.Input))
		out, err := s.Scan()
		if tt.Error {
			if err == nil {
				t.Errorf("expected error for %v", tt.Name)
			}
		} else {
			if err != nil {
				t.Errorf("didn't expect error for %v, got %v", tt.Name, err)
			} else if !reflect.DeepEqual(tt.Output, out) {
				t.Errorf("%v, have \n%v\n want \n%v", tt.Name, out, tt.Output)
			}
		}
	}
}

func TestEmptyLine(t *testing.T) {
	incorrectInput := []string{
		"",
		"asdf",
	}
	for _, test := range incorrectInput {
		s := NewScanner(strings.NewReader(test))
		if s.scanEmptyLine() == nil {
			t.Errorf("scanEmptyLine() should return error for line %q", test)
		}
	}
}
