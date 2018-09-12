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

package grpcutil

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetSslServerCreds_onNoCertsNorKey_returnsNil(t *testing.T) {
	opts, err := GetSslServerCreds("", "", "")
	require.NoError(t, err)
	require.Nil(t, opts)
}

func TestGetSslServerCreds_onOnlyCertOfKeySet_returnsError(t *testing.T) {
	_, err := GetSslServerCreds("something", "", "")
	require.Error(t, err)
	_, err = GetSslServerCreds("", "something", "")
	require.Error(t, err)
}

func TestGetSslServerCreds_onInvalidCerts_returnsError(t *testing.T) {
	basepath, err := os.Getwd()
	grb := basepath + "/testdata/garbage"
	_, err = GetSslServerCreds(grb, grb, "")
	require.Error(t, err)
}

func TestGetSslServerCreds_onValidCertsAndKeys_doesNotErrorOut(t *testing.T) {
	basepath, err := os.Getwd()
	crt := basepath + "/testdata/127.0.0.1.crt"
	key := basepath + "/testdata/127.0.0.1.key"
	_, err = GetSslServerCreds(crt, key, "")
	require.NoError(t, err)
}

func TestGetSslServerCreds_onValidCertsAndKeysAndCa_doesNotErrorOut(t *testing.T) {
	basepath, err := os.Getwd()
	crt := basepath + "/testdata/127.0.0.1.crt"
	key := basepath + "/testdata/127.0.0.1.key"
	ca := basepath + "/testdata/test_ca.crt"
	_, err = GetSslServerCreds(crt, key, ca)
	require.NoError(t, err)
}

func TestGetSslClientOptions_onNonExistingPathOrGarbage_returnsError(t *testing.T) {
	_, err := GetSslClientOptions("google.com", "INVALID")
	require.Error(t, err)
	basepath, err := os.Getwd()
	grb := basepath + "/testdata/garbage"
	_, err = GetSslClientOptions("google.com", grb)
	require.Error(t, err)
}

func TestGetSslClientOptions_onNoCa_returnsNoError(t *testing.T) {
	_, err := GetSslClientOptions("google.com", "")
	require.NoError(t, err)
	// Note I'd love to check if it returns WithInsecure, but function equality in go is impossible AFAICU.
}

func TestGetSslClientOptions_onCA_returnNoError(t *testing.T) {
	basepath, err := os.Getwd()
	crt := basepath + "/testdata/test_ca.crt"
	_, err = GetSslClientOptions("google.com", crt)
	require.NoError(t, err)
}
