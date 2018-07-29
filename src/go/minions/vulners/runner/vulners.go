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

package main

import (
	"flag"

	"github.com/google/minions/go/minions"
	"github.com/google/minions/go/minions/vulners"
)

var (
	apiKey = flag.String("vulners_api_key", "", "API key to use when calling Vulners")
)

func main() {
	flag.Parse()
	minions.StartMinion(vulners.NewMinion(*apiKey), "Vulners - Package checker")
}
