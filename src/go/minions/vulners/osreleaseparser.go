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

package vulners

// A parser for the os-release file extracting version and OS data.

import (
	"bufio"
	"errors"
	"io"
	"strings"
)

func parseOsReleaseLine(line string) (key string, value string, err error) {
	// Skip empty lines and comments
	if line[0] == '#' || len(line) == 0 {
		err = errors.New("Skip the line")
		return
	}

	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		err = errors.New("Not enough or too many =s")
		return
	}

	key = strings.Trim(parts[0], " ")
	value = stripAndExpand(strings.Trim(parts[1], " "))
	return
}

func stripAndExpand(in string) string {
	out := in
	// Quotes (ok, this might over-match)
	out = strings.TrimPrefix(out, `'`)
	out = strings.TrimPrefix(out, `"`)
	out = strings.TrimSuffix(out, `'`)
	out = strings.TrimSuffix(out, `"`)
	// Expansion
	out = strings.Replace(out, `\"`, `"`, -1)
	out = strings.Replace(out, `\$`, `$`, -1)
	out = strings.Replace(out, `\\`, `\`, -1)
	out = strings.Replace(out, "\\`", "`", -1)
	return out
}

func getOsAndversion(reader io.Reader) (operatingSystem string, version string, err error) {
	s := bufio.NewScanner(reader)
	var lines []string
	for s.Scan() {
		lines = append(lines, s.Text())
	}

	for _, line := range lines {
		k, v, err := parseOsReleaseLine(line)
		if err != nil {
			continue
		}
		switch k {
		case "NAME":
			operatingSystem = v
			break
		case "VERSION_ID":
			version = v
			break
		}
	}

	if operatingSystem == "" || version == "" {
		return "", "", errors.New("Could not identify os or version")
	}

	return operatingSystem, version, nil
}
