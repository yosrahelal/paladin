/*
 * Copyright © 2024 Kaleido, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/kaleido-io/paladin/registry/api"
	"github.com/kaleido-io/paladin/registry/config"
	"github.com/kaleido-io/paladin/registry/identity"
)

func main() {

	err := config.Values.Load()
	if err != nil {
		log.Fatalf("failed to load configuration: %s", err)
	}

	err = identity.Registry.Initialize(config.Values)
	if err != nil {
		panic(err)
	}

	mux := mux.NewRouter()
	api.SetupRest(mux)
	api.SetupJsonRpc(mux)

	fmt.Printf("Identity Registry running on port %d\n", config.Values.API.Port)
	err = http.ListenAndServe(fmt.Sprintf("localhost:%d", config.Values.API.Port), mux)
	if err != nil {
		log.Fatalf("failed to start server: %s", err)
	}
}
