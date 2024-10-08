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

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/kaleido-io/paladin/registry/identity"
)

type registerIdentityRequest struct {
	Signer string `json:"signer"`
	Name   string `json:"name"`
	Owner  string `json:"owner"`
}

type setIdentityPropertyRequest struct {
	Signer string `json:"signer"`
	Name   string `json:"name"`
	Value  string `json:"value"`
}

type deploySmartContractRequest struct {
	Signer string `json:"signer"`
}

type setSmartContractAddressRequest struct {
	Signer  string `json:"signer"`
	Address string `json:"address"`
}

func SetupRest(mux *mux.Router) {
	mux.PathPrefix("/api/v1/identities").HandlerFunc(lookupIdentityHandler).Methods("Get")
	mux.PathPrefix("/api/v1/identities").HandlerFunc(registerIdentityHandler).Methods("Post")
	mux.PathPrefix("/api/v1/identities").HandlerFunc(setIdentityPropertyHandler).Methods("Put")

	mux.PathPrefix("/api/v1/contract").HandlerFunc(smartContractStatusHandler).Methods("Get")
	mux.PathPrefix("/api/v1/contract").HandlerFunc(setSmartContractAddressHandler).Methods("Put")
	mux.PathPrefix("/api/v1/contract").HandlerFunc(deploySmartContractHandler).Methods("Post")

	mux.PathPrefix("/api/v1/sync").HandlerFunc(syncStatusHandler).Methods("Get")
	mux.PathPrefix("/api/v1/sync").HandlerFunc(syncHandler).Methods("Post")
}

func lookupIdentityHandler(w http.ResponseWriter, r *http.Request) {
	identifier := getIdentifierFromPath(r.URL.Path)
	result, err := lookupIdentity(identifier)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Failed to lookup identity: %s", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func registerIdentityHandler(w http.ResponseWriter, r *http.Request) {
	identifier := getIdentifierFromPath(r.URL.Path)
	var identityRequest registerIdentityRequest
	err := json.NewDecoder(r.Body).Decode(&identityRequest)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "Invalid identity")
		return
	}

	address, err := ethtypes.NewAddress(identityRequest.Owner)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "Invalid owner")
		return
	}

	result, err := registerIdentity(identityRequest.Signer, identifier, identityRequest.Name, *address)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Failed to register identity: %s", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func setIdentityPropertyHandler(w http.ResponseWriter, r *http.Request) {
	identifier := getIdentifierFromPath(r.URL.Path)
	var identityPropertyRequest setIdentityPropertyRequest
	err := json.NewDecoder(r.Body).Decode(&identityPropertyRequest)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "Invalid property")
		return
	}

	result, err := setIdentityProperty(identityPropertyRequest.Signer, identifier, identityPropertyRequest.Name, identityPropertyRequest.Value)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Failed to set property: %s", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func smartContractStatusHandler(w http.ResponseWriter, r *http.Request) {
	address, err := identity.Registry.GetSmartContractAddress()
	var result SmartContractStatusResult
	if err == nil {
		result.Address = address.String()
		result.Configured = true
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func setSmartContractAddressHandler(w http.ResponseWriter, r *http.Request) {
	var smartContractAddress setSmartContractAddressRequest
	err := json.NewDecoder(r.Body).Decode(&smartContractAddress)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "Invalid request")
		return
	}

	address, err := ethtypes.NewAddress(smartContractAddress.Address)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "Invalid smart contract address")
		return
	}

	result, err := setSmartContractAddress(*address)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Failed to set smart contract address %s", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func deploySmartContractHandler(w http.ResponseWriter, r *http.Request) {
	var deploySmartContractRequest deploySmartContractRequest
	err := json.NewDecoder(r.Body).Decode(&deploySmartContractRequest)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "Invalid request")
		return
	}

	result, err := deploySmartContract(deploySmartContractRequest.Signer)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Failed to deploy smart contract %s", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func syncStatusHandler(w http.ResponseWriter, r *http.Request) {
	result := SyncStatusResult{
		LastSync:              identity.Registry.LastSync,
		LastIncrementalUpdate: identity.Registry.LastIncrementalUpdate,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func syncHandler(w http.ResponseWriter, r *http.Request) {
	err := identity.Registry.SyncCache()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Failed to sync %s", err)
		return
	}

	result := SyncStatusResult{
		LastSync:              identity.Registry.LastSync,
		LastIncrementalUpdate: identity.Registry.LastIncrementalUpdate,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func getIdentifierFromPath(path string) string {
	return strings.Join(strings.Split(path, "/")[4:], "/")
}
