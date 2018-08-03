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
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/context"
	"golang.org/x/time/rate"
	resty "gopkg.in/resty.v1"
)

var (
	// ErrCpeFormat is thrown if the user supplied a malformed CPE identifier.
	ErrCpeFormat = errors.New("Invalid CPE format")
)

// A Client for the vulners APIs for Golang.
type Client struct {
	baseURL *url.URL
	apiKey  string
	limiter *rate.Limiter
}

// NewClient creates a new Client with the default baseURL, the specified
// API key and a default rate limiter, which only allows a few concurrent
// requests: limits are higher if an API key is provided.
func NewClient(apiKey string) *Client {
	var url *url.URL
	url, _ = url.Parse("https://vulners.com/api/v3")
	// If we have an API key, we can go a bit faster.
	var limiter *rate.Limiter
	if apiKey != "" {
		limiter = rate.NewLimiter(10, 20)
	} else {
		limiter = rate.NewLimiter(5, 10)
	}
	return &Client{baseURL: url, apiKey: apiKey, limiter: limiter}
}

// setNewLimitIfNeeded looks at the response headers from vulners and, if needed
// defines new rate limits. This function has side effects on the limiter.
func (c *Client) setNewLimitIfNeeded(response *resty.Response) error {

	// Now check to see if the Vulners backend tells us to slow down.
	limitS := response.Header().Get("X-Vulners-Ratelimit-Reqlimit")
	currRateS := response.Header().Get("X-Vulners-Ratelimit-Rate")
	if currRateS != "" {
		currRate, err := strconv.ParseFloat(currRateS, 64)
		if err != nil {
			return fmt.Errorf("Cannot parse X-Vulners-Ratelimit-Rate header: %s", currRateS)
		}
		limit, err := strconv.ParseFloat(limitS, 64)
		if err != nil {
			return fmt.Errorf("Cannot parse X-Vulners-Ratelimit-Reqlimit header: %s", limitS)
		}

		newLimit := rate.Limit(limit)
		// Check if we need to slow down and do so if needed, or raise the limit if possible.
		if currRate > limit {
			// Shoot for 80% of the limit, trying to be nice.
			actualLimit := limit * 80 / 100
			// Now very, very slowly ramp up the amount of requests similar to what
			// the Vulners Python APIs do.
			rateDifference := (currRate / (actualLimit / 100)) / 60
			newLimit = rate.Limit((rateDifference * actualLimit) / 100.0)
		}
		fmt.Printf("Ok, setting limit %f \n", newLimit)
		c.limiter.SetLimit(newLimit)
	}
	return nil
}

// GetVulnerabilitiesForCpe returns all known vulnerabilities from Vulners for the
// given CPE, erroring out if there are more than maxVulnerabilities. Yes, that's
// not a very reasonable behavior, so just specify something large and a future
// version of this client might implement some form of client-side paging.
func (c *Client) GetVulnerabilitiesForCpe(ctx context.Context, cpe string, maxVulnerabilities int) (result string, err error) {
	c.limiter.Wait(ctx)
	r, err := c.getVulnerabilitiesForCpe(cpe, maxVulnerabilities)
	if err != nil {
		return "", err
	}
	err = c.setNewLimitIfNeeded(r)
	if err != nil {
		return "", err
	}

	return r.String(), nil
}

func (c *Client) getVulnerabilitiesForCpe(cpe string, maxVulnerabilities int) (result *resty.Response, err error) {
	type getCpeVulnMessage struct {
		Software           string `json:"software"`
		Version            string `json:"version"`
		MaxVulnerabilities int    `json:"maxVulnerabilities"`
		Type               string `json:"type"`
		APIKey             string `json:"apiKey"`
	}

	// Note that the APIs default behavior is to error out (402 - "Too much results") if
	// there are more than maxVulnerabilities. Sigh.
	if maxVulnerabilities < 0 {
		return nil, errors.New("Specify positive max vulnerabilities (use a large number if in doubt)")
	}
	if len(strings.Split(cpe, ":")) <= 4 {
		return nil, ErrCpeFormat
	}
	slicedCpe := strings.Split(cpe, ":")
	version := slicedCpe[4]

	// Now build the json payload
	msg := getCpeVulnMessage{
		Software:           cpe,
		Version:            version,
		MaxVulnerabilities: maxVulnerabilities,
		Type:               "cpe",
		APIKey:             c.apiKey,
	}
	json, err := json.Marshal(msg)

	resp, _ := resty.R().
		SetHeader("Content-Type", "application/json").
		SetBody(json).
		Post(fmt.Sprintf("%s/burp/software", c.baseURL.String()))

	return resp, nil
}

// Useful data types for the audit calls below
type cvssScore struct {
	Score  float32 `json:"score"`
	Vector string  `json:"vector"`
}

type vulnPackage struct {
	Package          string    `json:"package"`
	ProvidedVersion  string    `json:"providedVersion"`
	BulletinVersion  string    `json:"bulletinVersion"`
	ProvidedPackage  string    `json:"providedPackage"`
	BulletingPackage string    `json:"bulletinPackage"`
	Operator         string    `json:"operator"`
	BulletinID       string    `json:"bulletinID"`
	CveList          []string  `json:"cvelist"`
	Cvss             cvssScore `json:"cvss"`
	Fix              string    `json:"fix"`
}

type vulnResponseData struct {
	Cvss          cvssScore `json:"cvss"`
	CveList       []string  `json:"cvelist"`
	Packages      map[string]map[string][]vulnPackage
	Error         string `json:"error"`
	ErrorCode     int    `json:"errorCode"`
	CumulativeFix string `json:"cumulativeFix"`
}

// VulnResponse contains the response to a query on the vulnerability state
// of a set of packages.
type VulnResponse struct {
	Result string           `json:"result"`
	Data   vulnResponseData `json:"data"`
}

// GetVulnerabilitiesForPackages returns all known vulnerabilities from Vulners for the
// combination of operating system, package and version.
func (c *Client) GetVulnerabilitiesForPackages(ctx context.Context, os string, osVersion string, packages []string) (*VulnResponse, error) {
	c.limiter.Wait(ctx)
	resp, err := c.getVulnerabilitiesForPackages(os, osVersion, packages)
	if err != nil {
		return nil, err
	}
	err = c.setNewLimitIfNeeded(resp)
	if err != nil {
		return nil, err
	}

	r := resp.Result().(*VulnResponse)
	if r.Result == "ERROR" {
		return nil, errors.New("ERROR response from API backend: " + r.Data.Error)
	}
	return r, nil
}

func (c *Client) getVulnerabilitiesForPackages(os string, osVersion string, packages []string) (*resty.Response, error) {
	type getVulnForPkg struct {
		OS      string   `json:"os"`
		Version string   `json:"version"`
		Package []string `json:"package"`
		APIKey  string   `json:"apiKey"`
	}
	msg := getVulnForPkg{
		OS:      os,
		Version: osVersion,
		Package: packages,
		APIKey:  c.apiKey,
	}
	json, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	// Handy for debugging.
	//resty.SetDebug(true)

	resp, err := resty.R().
		SetHeader("Content-Type", "application/json").
		SetBody(json).
		SetResult(&VulnResponse{}). // Throw the response directly in a JSON structure
		Post(fmt.Sprintf("%s/audit/audit", c.baseURL.String()))
	if err != nil {
		return nil, err
	}
	return resp, nil
}
