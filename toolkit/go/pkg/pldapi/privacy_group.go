// Copyright © 2024 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pldapi

import (
	"github.com/google/uuid"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

type PrivacyGroup struct {
	ID                 tktypes.HexBytes    `docstruct:"PrivacyGroup" json:"id"`
	Domain             string              `docstruct:"PrivacyGroup" json:"domain"`
	Created            tktypes.Timestamp   `docstruct:"PrivacyGroup" json:"created"`
	Members            []string            `docstruct:"PrivacyGroup" json:"members"`
	ContractAddress    *tktypes.EthAddress `docstruct:"PrivacyGroup" json:"contractAddress"`
	Genesis            tktypes.RawJSON     `docstruct:"PrivacyGroup" json:"genesis,omitempty"` // full genesis state
	GenesisTransaction uuid.UUID           `docstruct:"PrivacyGroup" json:"genesisTransaction"`
	GenesisSchema      tktypes.Bytes32     `docstruct:"PrivacyGroup" json:"genesisSchema"`
	GenesisSignature   string              `docstruct:"PrivacyGroup" json:"genesisSignature"`
}

type PrivacyGroupTXOptions struct {
	IdempotencyKey string `docstruct:"PrivacyGroup" json:"idempotencyKey,omitempty"`
	PublicTxOptions
}

type PrivacyGroupInput struct {
	Domain             string                 `docstruct:"PrivacyGroup" json:"domain"`
	Members            []string               `docstruct:"PrivacyGroup" json:"members"`
	Properties         tktypes.RawJSON        `docstruct:"PrivacyGroup" json:"properties"`              // properties that inform genesis state
	PropertiesABI      abi.ParameterArray     `docstruct:"PrivacyGroup" json:"propertiesABI,omitempty"` // without this the property types will be inferred
	TransactionOptions *PrivacyGroupTXOptions `docstruct:"PrivacyGroup" json:"transactionOptions,omitempty"`
}
