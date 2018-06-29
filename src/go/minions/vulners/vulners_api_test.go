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

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetVulnerabilitiesForCpe(t *testing.T) {
	ts := createCpeServer(t)
	defer ts.Close()

	c := newClient("irrelevant")
	url, _ := url.Parse(ts.URL)
	c.baseURL = url

	results, err := c.getVulnerabilitiesForCpe("cpe:/a:cybozu:garoon:4.2.1", 1)
	assert.Nil(t, err)
	var dat map[string]interface{}
	if err := json.Unmarshal([]byte(results), &dat); err != nil {
		t.Error(err)
	}
	assert.Equal(t, dat["result"], "OK")
}

func TestGetVulnerabilitiesForPackages(t *testing.T) {
	ts := createPkgServer(t)
	defer ts.Close()

	c := newClient("irrelevant")
	url, _ := url.Parse(ts.URL)
	c.baseURL = url

	pkgs := []string{"pcre-8.32-15.el7.x86_64"}
	result, err := c.getVulnerabilitiesForPackages("debian", "7", pkgs)
	assert.Nil(t, err)
	assert.Equal(t, "OK", result.Result)
}

func TestInvalidCpeString(t *testing.T) {
	c := newClient("irrelevant")
	_, err := c.getVulnerabilitiesForCpe("totallynotcpe", 1)
	assert.Equal(t, ErrCpeFormat, err)
}

func TestNegativeMaxVulns(t *testing.T) {
	c := newClient("irrelevant")
	_, err := c.getVulnerabilitiesForCpe("cpe:/a:cybozu:garoon:4.2.1", -1)
	assert.Error(t, err)
}

func createPkgServer(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Method: %v", r.Method)
		t.Logf("Path: %v", r.URL.Path)
		switch r.URL.Path {
		case "/audit/audit":
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				t.Errorf("Error: expected request for Audit: %s", err.Error())
			}
			var dat map[string]interface{}
			if err := json.Unmarshal(body, &dat); err != nil {
				t.Fatalf("Got an error parsing JSON request: %s", err)
			}
			assertContainsJSONElement(t, dat, "os")
			assertContainsJSONElement(t, dat, "version")
			assertContainsJSONElement(t, dat, "package")
			// Needed as the APIs parse the response
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			response := `
			{
				 "result": "OK",
				 "data": {
						"packages": {
							 "gnupg 1.4.22 x86_64": {
									"USN-3675-1": [
										 {
												"package": "gnupg 1.4.22 x86_64",
												"providedVersion": "1.4.22",
												"bulletinVersion": "2.2.4-1ubuntu1.1",
												"providedPackage": "gnupg 1.4.22 x86_64",
												"bulletinPackage": "UNKNOWN",
												"operator": "lt",
												"bulletinID": "USN-3675-1",
												"cvelist": [
													 "CVE-2018-12020",
													 "CVE-2018-9234"
												],
												"cvss": {
													 "score": 5.0,
													 "vector": "AV:NETWORK/AC:LOW/Au:NONE/C:PARTIAL/I:NONE/A:NONE/"
												},
												"fix": "sudo apt-get --assume-yes install --only-upgrade gnupg"
										 }
									]
							 }
						},
						"vulnerabilities": [
							 "USN-3675-1"
						],
						"reasons": [
							 {
									"package": "gnupg 1.4.22 x86_64",
									"providedVersion": "1.4.22",
									"bulletinVersion": "2.2.4-1ubuntu1.1",
									"providedPackage": "gnupg 1.4.22 x86_64",
									"bulletinPackage": "UNKNOWN",
									"operator": "lt",
									"bulletinID": "USN-3675-1",
									"cvelist": [
										 "CVE-2018-12020",
										 "CVE-2018-9234"
									],
									"cvss": {
										 "score": 5.0,
										 "vector": "AV:NETWORK/AC:LOW/Au:NONE/C:PARTIAL/I:NONE/A:NONE/"
									},
									"fix": "sudo apt-get --assume-yes install --only-upgrade gnupg"
							 }
						],
						"cvss": {
							 "score": 7.5,
							 "vector": "AV:NETWORK/AC:LOW/Au:NONE/C:PARTIAL/I:PARTIAL/A:PARTIAL/"
						},
						"cvelist": [
							 "CVE-2018-12020",
							 "CVE-2018-9234"
						],
						"cumulativeFix": "sudo apt-get --assume-yes install --only-upgrade xdg-utils",
						"id": "foo"
				 }
			}`
			w.Write([]byte(response))
		default:
			t.Fatalf("Unrecognized path requested %v", r.URL.Path)
		}
	}))
}

func createCpeServer(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Method: %v", r.Method)
		t.Logf("Path: %v", r.URL.Path)
		switch r.URL.Path {
		case "/burp/software":
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				t.Errorf("Error: expected request for CPE: %s", err.Error())
			}
			var dat map[string]interface{}
			if err := json.Unmarshal(body, &dat); err != nil {
				t.Fatalf("Got an error parsing JSON request: %s", err)
			}
			assertContainsJSONElement(t, dat, "software")
			assertContainsJSONElement(t, dat, "type")
			assertContainsJSONElement(t, dat, "version")
			assertContainsJSONElement(t, dat, "maxVulnerabilities")
			assert.Equal(t, dat["type"], "cpe")
			response := `{"result": "OK", "data": {
				"search": [
					{
						"_index": "bulletins",
						"_type": "bulletin",
						"_id": "CVE-2017-2254",
						"_score": 1.1596423e-05,
						"_source": {
							"lastseen": "2017-08-31T17:16:36",
							"bulletinFamily": "NVD",
							"description": "Description",
							"modified": "2017-08-30T10:44:51",
							"published": "2017-08-28T21:35:13",
							"id": "CVE-2017-2254",
							"href": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2017-2254",
							"title": "CVE-2017-2254",
							"type": "cve",
							"cvss": {
								"score": 4.0,
								"vector": "AV:NETWORK/AC:LOW/Au:SINGLE_INSTANCE/C:NONE/I:NONE/A:PARTIAL/"
							}
						},
						"highlight": {
							"history.bulletin.reporter": [
								"<span class=\"vulners-highlight\">NVD</span>"
							],
							"bulletinFamily": [
								"<span class=\"vulners-highlight\">NVD</span>"
							],
							"cpe": [
								"<span class=\"vulners-highlight\">cpe</span>:/<span class=\"vulners-highlight\">a:cybozu:garoon</span>:<span class=\"vulners-highlight\">4.2.1</span>"
							],
							"history.bulletin.bulletinFamily": [
								"<span class=\"vulners-highlight\">NVD</span>"
							],
							"reporter": [
								"<span class=\"vulners-highlight\">NVD</span>"
							]
						},
						"sort": [
							1.1596423e-05,
							1503956113000
						]
					}
				]
			}}`
			w.Write([]byte(response))
		default:
			t.Fatalf("Unrecognized path requested %v", r.URL.Path)
		}
	}))
}

func assertContainsJSONElement(t *testing.T, v map[string]interface{}, key string) {
	if _, keyPresent := v[key]; !keyPresent {
		t.Fatalf("JSON request does not contain %s", key)
	}
}
