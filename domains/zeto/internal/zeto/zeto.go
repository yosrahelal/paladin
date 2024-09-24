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

package zeto

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/kaleido-io/paladin/core/pkg/blockindexer"
	"github.com/kaleido-io/paladin/core/pkg/persistence"
	"github.com/kaleido-io/paladin/domains/zeto/pkg/types"
	"github.com/kaleido-io/paladin/toolkit/pkg/algorithms"
	"github.com/kaleido-io/paladin/toolkit/pkg/domain"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/plugintk"
	"github.com/kaleido-io/paladin/toolkit/pkg/prototk"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

//go:embed abis/ZetoFactory.json
var factoryJSONBytes []byte // From "gradle copySolidity"
//go:embed abis/IZetoFungibleInitializable.json
var zetoFungibleInitializableABIBytes []byte // From "gradle copySolidity"
//go:embed abis/IZetoNonFungibleInitializable.json
var zetoNonFungibleInitializableABIBytes []byte // From "gradle copySolidity"

type Zeto struct {
	Callbacks plugintk.DomainCallbacks

	config                   *types.DomainFactoryConfig
	chainID                  int64
	coinSchema               *prototk.StateSchema
	factoryABI               abi.ABI
	mintSignature            string
	transferSignature        string
	transferWithEncSignature string

	// temporary until we have an interface to the state DB
	// that supports inserts
	SmtStorage persistence.Persistence
}

type MintEvent struct {
	Outputs []tktypes.HexInteger `json:"outputs"`
	Data    tktypes.HexBytes     `json:"data"`
}

type TransferEvent struct {
	Inputs  []tktypes.HexInteger `json:"inputs"`
	Outputs []tktypes.HexInteger `json:"outputs"`
	Data    tktypes.HexBytes     `json:"data"`
}

type TransferWithEncryptedValuesEvent struct {
	Inputs          []tktypes.HexInteger `json:"inputs"`
	Outputs         []tktypes.HexInteger `json:"outputs"`
	Data            tktypes.HexBytes     `json:"data"`
	EncryptionNonce tktypes.HexInteger   `json:"encryptionNonce"`
	EncryptedValues []tktypes.HexInteger `json:"encryptedValues"`
}

func New(callbacks plugintk.DomainCallbacks) *Zeto {
	return &Zeto{
		Callbacks: callbacks,
	}
}

func (z *Zeto) ConfigureDomain(ctx context.Context, req *prototk.ConfigureDomainRequest) (*prototk.ConfigureDomainResponse, error) {
	var config types.DomainFactoryConfig
	err := json.Unmarshal([]byte(req.ConfigJson), &config)
	if err != nil {
		return nil, err
	}

	z.config = &config
	z.chainID = req.ChainId

	factory := domain.LoadBuildLinked(factoryJSONBytes, config.Libraries)
	z.factoryABI = factory.ABI

	schemaJSON, err := json.Marshal(types.ZetoCoinABI)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Zeto Coin schema abi. %s", err)
	}

	events := getAllZetoEventAbis()
	eventsJSON, err := json.Marshal(events)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Zeto event abis. %s", err)
	}

	z.registerEventSignatures(events)

	return &prototk.ConfigureDomainResponse{
		DomainConfig: &prototk.DomainConfig{
			AbiStateSchemasJson: []string{string(schemaJSON)},
			BaseLedgerSubmitConfig: &prototk.BaseLedgerSubmitConfig{
				SubmitMode: prototk.BaseLedgerSubmitConfig_ENDORSER_SUBMISSION,
			},
			AbiEventsJson: string(eventsJSON),
		},
	}, nil
}

func (z *Zeto) InitDomain(ctx context.Context, req *prototk.InitDomainRequest) (*prototk.InitDomainResponse, error) {
	z.coinSchema = req.AbiStateSchemas[0]
	return &prototk.InitDomainResponse{}, nil
}

func (z *Zeto) InitDeploy(ctx context.Context, req *prototk.InitDeployRequest) (*prototk.InitDeployResponse, error) {
	initParams, err := z.validateDeploy(req.Transaction)
	if err != nil {
		return nil, err
	}
	return &prototk.InitDeployResponse{
		RequiredVerifiers: []*prototk.ResolveVerifierRequest{
			{
				Lookup:    initParams.From,
				Algorithm: algorithms.ECDSA_SECP256K1_PLAINBYTES,
			},
		},
	}, nil
}

func (z *Zeto) PrepareDeploy(ctx context.Context, req *prototk.PrepareDeployRequest) (*prototk.PrepareDeployResponse, error) {
	initParams, err := z.validateDeploy(req.Transaction)
	if err != nil {
		return nil, err
	}
	circuitId, err := z.config.GetCircuitId(initParams.TokenName)
	if err != nil {
		return nil, err
	}
	config := &types.DomainInstanceConfig{
		CircuitId: circuitId,
		TokenName: initParams.TokenName,
	}
	configJSON, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	encoded, err := types.DomainInstanceConfigABI.EncodeABIDataJSONCtx(ctx, configJSON)
	if err != nil {
		return nil, err
	}

	deployParams := &types.DeployParams{
		TransactionID: req.Transaction.TransactionId,
		Data:          ethtypes.HexBytes0xPrefix(encoded),
		TokenName:     initParams.TokenName,
		InitialOwner:  req.ResolvedVerifiers[0].Verifier, // TODO: allow the initial owner to be specified by the deploy request
	}
	paramsJSON, err := json.Marshal(deployParams)
	if err != nil {
		return nil, err
	}
	functionJSON, err := json.Marshal(z.factoryABI.Functions()["deploy"])
	if err != nil {
		return nil, err
	}

	return &prototk.PrepareDeployResponse{
		Transaction: &prototk.BaseLedgerTransaction{
			FunctionAbiJson: string(functionJSON),
			ParamsJson:      string(paramsJSON),
		},
		Signer: &initParams.From,
	}, nil
}

func (z *Zeto) InitTransaction(ctx context.Context, req *prototk.InitTransactionRequest) (*prototk.InitTransactionResponse, error) {
	tx, handler, err := z.validateTransaction(ctx, req.Transaction)
	if err != nil {
		return nil, err
	}
	return handler.Init(ctx, tx, req)
}

func (z *Zeto) AssembleTransaction(ctx context.Context, req *prototk.AssembleTransactionRequest) (*prototk.AssembleTransactionResponse, error) {
	tx, handler, err := z.validateTransaction(ctx, req.Transaction)
	if err != nil {
		return nil, err
	}
	return handler.Assemble(ctx, tx, req)
}

func (z *Zeto) EndorseTransaction(ctx context.Context, req *prototk.EndorseTransactionRequest) (*prototk.EndorseTransactionResponse, error) {
	tx, handler, err := z.validateTransaction(ctx, req.Transaction)
	if err != nil {
		return nil, err
	}
	return handler.Endorse(ctx, tx, req)
}

func (z *Zeto) PrepareTransaction(ctx context.Context, req *prototk.PrepareTransactionRequest) (*prototk.PrepareTransactionResponse, error) {
	tx, handler, err := z.validateTransaction(ctx, req.Transaction)
	if err != nil {
		return nil, err
	}
	return handler.Prepare(ctx, tx, req)
}

func (z *Zeto) decodeDomainConfig(ctx context.Context, domainConfig []byte) (*types.DomainInstanceConfig, error) {
	configValues, err := types.DomainInstanceConfigABI.DecodeABIDataCtx(ctx, domainConfig, 0)
	if err != nil {
		return nil, err
	}
	configJSON, err := tktypes.StandardABISerializer().SerializeJSON(configValues)
	if err != nil {
		return nil, err
	}
	var config types.DomainInstanceConfig
	err = json.Unmarshal(configJSON, &config)
	return &config, err
}

func (z *Zeto) validateDeploy(tx *prototk.DeployTransactionSpecification) (*types.InitializerParams, error) {
	var params types.InitializerParams
	err := json.Unmarshal([]byte(tx.ConstructorParamsJson), &params)
	return &params, err
}

func (z *Zeto) validateTransaction(ctx context.Context, tx *prototk.TransactionSpecification) (*types.ParsedTransaction, types.DomainHandler, error) {
	var functionABI abi.Entry
	err := json.Unmarshal([]byte(tx.FunctionAbiJson), &functionABI)
	if err != nil {
		return nil, nil, err
	}

	abi := types.ZetoABI.Functions()[functionABI.Name]
	handler := z.GetHandler(functionABI.Name)
	if abi == nil || handler == nil {
		return nil, nil, fmt.Errorf("unknown function: %s", functionABI.Name)
	}
	params, err := handler.ValidateParams(ctx, tx.FunctionParamsJson)
	if err != nil {
		return nil, nil, err
	}

	signature, _, err := abi.SolidityDefCtx(ctx)
	if err != nil {
		return nil, nil, err
	}
	if tx.FunctionSignature != signature {
		return nil, nil, fmt.Errorf("unexpected signature for function '%s': expected=%s actual=%s", functionABI.Name, signature, tx.FunctionSignature)
	}

	domainConfig, err := z.decodeDomainConfig(ctx, tx.ContractConfig)
	if err != nil {
		return nil, nil, err
	}

	contractAddress, err := ethtypes.NewAddress(tx.ContractAddress)
	if err != nil {
		return nil, nil, err
	}

	return &types.ParsedTransaction{
		Transaction:     tx,
		FunctionABI:     &functionABI,
		ContractAddress: contractAddress,
		DomainConfig:    domainConfig,
		Params:          params,
	}, handler, nil
}

func (z *Zeto) FindCoins(ctx context.Context, contractAddress ethtypes.Address0xHex, query string) ([]*types.ZetoCoin, error) {
	states, err := z.findAvailableStates(ctx, contractAddress.String(), query)
	if err != nil {
		return nil, err
	}

	coins := make([]*types.ZetoCoin, len(states))
	for i, state := range states {
		if coins[i], err = z.makeCoin(state.DataJson); err != nil {
			return nil, err
		}
	}
	return coins, err
}

func (z *Zeto) registerEventSignatures(eventAbis abi.ABI) {
	for _, event := range eventAbis.Events() {
		switch event.Name {
		case "UTXOMint":
			z.mintSignature = event.SolString()
		case "UTXOTransfer":
			z.transferSignature = event.SolString()
		case "UTXOTransferWithEncryptedValues":
			z.transferWithEncSignature = event.SolString()
		}
	}
}

func (z *Zeto) HandleEventBatch(ctx context.Context, req *prototk.HandleEventBatchRequest) (*prototk.HandleEventBatchResponse, error) {
	var events []*blockindexer.EventWithData
	if err := json.Unmarshal([]byte(req.JsonEvents), &events); err != nil {
		return nil, err
	}

	var res prototk.HandleEventBatchResponse
	for _, ev := range events {
		switch ev.SoliditySignature {
		case z.mintSignature:
			var mint MintEvent
			if err := json.Unmarshal(ev.Data, &mint); err == nil {
				txID := decodeTransactionData(mint.Data)
				res.TransactionsComplete = append(res.TransactionsComplete, txID.String())
				res.ConfirmedStates = append(res.ConfirmedStates, parseStatesFromEvent(txID, mint.Outputs)...)
			} else {
				log.L(ctx).Errorf("Failed to unmarshal mint event: %s", err)
			}
		case z.transferSignature:
			var transfer TransferEvent
			if err := json.Unmarshal(ev.Data, &transfer); err == nil {
				txID := decodeTransactionData(transfer.Data)
				res.TransactionsComplete = append(res.TransactionsComplete, txID.String())
				res.SpentStates = append(res.SpentStates, parseStatesFromEvent(txID, transfer.Inputs)...)
				res.ConfirmedStates = append(res.ConfirmedStates, parseStatesFromEvent(txID, transfer.Outputs)...)
				fmt.Printf("\nspent states: %+v\nconfirmed states: %+v\n", res.SpentStates, res.ConfirmedStates)
			} else {
				log.L(ctx).Errorf("Failed to unmarshal transfer event: %s", err)
			}
		case z.transferWithEncSignature:
			var transfer TransferWithEncryptedValuesEvent
			if err := json.Unmarshal(ev.Data, &transfer); err == nil {
				txID := decodeTransactionData(transfer.Data)
				res.TransactionsComplete = append(res.TransactionsComplete, txID.String())
				res.SpentStates = append(res.SpentStates, parseStatesFromEvent(txID, transfer.Inputs)...)
				res.ConfirmedStates = append(res.ConfirmedStates, parseStatesFromEvent(txID, transfer.Outputs)...)
			} else {
				log.L(ctx).Errorf("Failed to unmarshal transfer with encrypted values event: %s", err)
			}
		}
	}
	return &res, nil
}

func encodeTransactionData(ctx context.Context, transaction *prototk.TransactionSpecification) (tktypes.HexBytes, error) {
	txID, err := tktypes.ParseHexBytes(ctx, transaction.TransactionId)
	if err != nil {
		return nil, err
	}
	fmt.Printf("\nencoded transaction id: %s\n", txID.String())
	var data []byte
	data = append(data, types.ZetoTransactionData_V0...)
	data = append(data, txID...)
	return data, nil
}

func decodeTransactionData(data tktypes.HexBytes) (txID tktypes.HexBytes) {
	if len(data) < 4 {
		return nil
	}
	dataPrefix := data[0:4]
	if dataPrefix.String() != types.ZetoTransactionData_V0.String() {
		return nil
	}
	fmt.Printf("\ndecoded transaction id: %s\n", data[4:].String())
	return data[4:]
}

func parseStatesFromEvent(txID tktypes.HexBytes, states []tktypes.HexInteger) []*prototk.StateUpdate {
	refs := make([]*prototk.StateUpdate, len(states))
	for i, state := range states {
		refs[i] = &prototk.StateUpdate{
			Id:            state.String(),
			TransactionId: txID.String(),
		}
	}
	return refs
}
