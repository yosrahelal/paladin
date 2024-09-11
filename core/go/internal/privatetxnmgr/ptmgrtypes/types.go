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

package ptmgrtypes

import (
	"context"
	"time"

	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/statestore"
	"github.com/kaleido-io/paladin/core/pkg/ethclient"
)

type StageProcessNextStep int

const (
	NextStepWait StageProcessNextStep = iota
	NextStepNewStage
	NextStepNewAction
)

type StageEvent struct {
	ID              string      `json:"id"` // TODO: not sure how useful it is to have this ID as the process of event should be idempotent?
	Stage           string      `json:"stage"`
	ContractAddress string      `json:"contractAddress"`
	TxID            string      `json:"transactionId"`
	Data            interface{} `json:"data"` // schema decided by each stage
}

type StageChangeEvent struct {
	ID              string      `json:"id"`
	PreviousStage   string      `json:"previousStage"`
	NewStage        string      `json:"newStage"`
	ContractAddress string      `json:"contractAddress"`
	TxID            string      `json:"transactionId"`
	Data            interface{} `json:"data"` // schema decided by each stage
}

type TransactionDispatchedEvent struct {
	TransactionID  string `json:"transactionId"`
	Nonce          uint64 `json:"nonce"`
	SigningAddress string `json:"signingAddress"`
}

type TxProcessPreReq struct {
	TxIDs []string `json:"transactionIds,omitempty"`
}

type TxStatus struct {
	TxID   string `json:"transactionId"`
	Status string `json:"status"`
}

type MockIdentityResolver struct {
}

func (mti *MockIdentityResolver) IsCurrentNode(nodeID string) bool {
	return nodeID == "current-node"
}

func (mti *MockIdentityResolver) GetDispatchAddress(preferredAddresses []string) string {
	if len(preferredAddresses) > 0 {
		return preferredAddresses[0]
	}
	return ""
}

func (mti *MockIdentityResolver) ConnectToBaseLeger() error {
	return nil
}

type EndorsementRequest struct {
	TransactionID string
	InputStates   []string
}

type Transaction struct {
	ID              string
	AssemblerNodeID string
	OutputStates    []string
	InputStates     []string
}

type StageContext struct {
	Ctx            context.Context
	ID             string
	Stage          string
	StageEntryTime time.Time
}

type EventSubscriber func(event EngineEvent)

type EngineEvent interface {
}

type StageFoundationService interface {
	TransportManager() components.TransportManager
	DomainAPI() components.DomainSmartContract
	StateStore() statestore.StateStore // TODO: filter out to only getters so setters can be coordinated efficiently like transactions
	KeyManager() ethclient.KeyManager
}
