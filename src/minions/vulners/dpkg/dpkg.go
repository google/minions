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
Package dpkg reads package information in the format of /var/lib/dpkg/status file.

A dpkg status file contains information about installed deb packages. There should
be an empty line after each package in a file.

Keys are changed to lower case.

Whitespace from the beginning and end of values is discarded.

Example:

Package: libnotify-bin
Status: install ok installed
Priority: optional
Installed-Size: 69
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Version: 0.7.6-1ubuntu3
Depends: libc6 (>= 2.3.4), libglib2.0-0 (>= 2.26), libnotify4 (>= 0.7.3)
Description: sends desktop notifications to a notification daemon (Utilities)
 This package contains the binary which sends the notification.
Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>

Package: next
...
*/
package dpkg

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
	"unicode"
)

// Entry represents information about package, like version, description etc.
type Entry map[string]string

// A Scanner reads entries from the file.
type Scanner struct {
	reader *bufio.Reader
}

// NewScanner returns a new Scanner that reads from r.
func NewScanner(r io.Reader) *Scanner {
	return &Scanner{reader: bufio.NewReader(r)}
}

// Scan reads one Entry (package info) from s.
// A successful call returns err == nil. It returns io.EOF as error when
// the scanner has reached end of file.
// Important note: keys in returned Entry are lowercase.
func (s *Scanner) Scan() (Entry, error) {
	block := make(Entry)

	for {
		ch, err := s.peek()
		if err != nil {
			return nil, err
		} else if unicode.IsSpace(rune(ch)) {
			return block, s.scanEmptyLine()
		}

		key, value, err := s.scanPair()
		if err != nil {
			return nil, err
		}
		block[key] = value
	}
}

// scanPair reads and returns one key: value pair from s.
func (s *Scanner) scanPair() (key, value string, err error) {
	key, err = s.scanKey()
	if err != nil {
		return "", "", err
	}

	value, err = s.scanValue()
	if err != nil {
		return "", "", err
	}

	return key, value, err
}

// scanKey reads next key from s and returns it as a string.
// Key is defined as a string ending with ':'. Error is returned
// if ReadString(':') encounters an error or there was an error
// while reading optional trailing '\n' - eof, read errors, etc.
// Returned key is lowercase.
func (s *Scanner) scanKey() (string, error) {
	key, err := s.reader.ReadString(':')
	if err != nil {
		return "", err
	}

	// Value for that key may start on the same line, or on the next
	// one - in that case we need to ignore the new line.
	if ch, err := s.peek(); err != nil {
		return "", err
	} else if ch == '\n' {
		_, err := s.reader.ReadByte()
		if err == io.EOF {
			return "", io.ErrUnexpectedEOF
		} else if err != nil {
			return "", err
		}
	}

	return strings.ToLower(key[:len(key)-1]), nil
}

// scanValue reads next value from s and returns it as a string.
// Value is defined as everything up to next non-indented line and is
// trimmed of excess whitespace. Error is returned if scanner hits end
// of file or if ReadString('\n') encounters an error.
func (s *Scanner) scanValue() (string, error) {
	var output bytes.Buffer

	for {
		ch, err := s.peek()
		if err == io.EOF {
			return "", io.ErrUnexpectedEOF
		} else if err != nil {
			return "", err
		} else if ch != ' ' {
			break
		}

		line, err := s.reader.ReadString('\n')
		if err == io.EOF {
			return "", io.ErrUnexpectedEOF
		} else if err != nil {
			return "", err
		}
		output.WriteString(line)
	}
	return strings.TrimSpace(output.String()), nil
}

// peek returns next byte that will be read from s without advancing the scanner.
func (s *Scanner) peek() (byte, error) {
	ch, err := s.reader.Peek(1)
	if err != nil {
		return 0, err
	}
	return ch[0], nil
}

// scanEmptyLine reads a line from s returning errors when there was no line to
// read or when there were non-whitespace characters present.
func (s *Scanner) scanEmptyLine() error {
	line, err := s.reader.ReadString('\n')
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(line)) > 0 {
		return fmt.Errorf("expected empty line, got %q", line)
	}
	return nil
}
