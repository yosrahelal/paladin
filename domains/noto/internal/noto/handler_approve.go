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

package noto

import (
	"context"
	"encoding/json"

	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/kaleido-io/paladin/domains/noto/internal/msgs"
	"github.com/kaleido-io/paladin/domains/noto/pkg/types"
	"github.com/kaleido-io/paladin/toolkit/pkg/algorithms"
	"github.com/kaleido-io/paladin/toolkit/pkg/domain"
	"github.com/kaleido-io/paladin/toolkit/pkg/prototk"
	"github.com/kaleido-io/paladin/toolkit/pkg/signpayloads"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/kaleido-io/paladin/toolkit/pkg/verifiers"
)

type approveHandler struct {
	noto *Noto
}

type TransferWithApprovalParams struct {
	Inputs  []interface{}             `json:"inputs"`
	Outputs []interface{}             `json:"outputs"`
	Data    ethtypes.HexBytes0xPrefix `json:"data"`
}

func (h *approveHandler) ValidateParams(ctx context.Context, config *types.NotoConfigOutput_V0, params string) (interface{}, error) {
	var approveParams types.ApproveParams
	if err := json.Unmarshal([]byte(params), &approveParams); err != nil {
		return nil, err
	}
	_, err := h.decodeTransferCall(context.Background(), approveParams.Call)
	if err != nil {
		return nil, err
	}
	return &approveParams, nil
}

func (h *approveHandler) Init(ctx context.Context, tx *types.ParsedTransaction, req *prototk.InitTransactionRequest) (*prototk.InitTransactionResponse, error) {
	return &prototk.InitTransactionResponse{
		RequiredVerifiers: []*prototk.ResolveVerifierRequest{
			{
				Lookup:       tx.Transaction.From,
				Algorithm:    algorithms.ECDSA_SECP256K1,
				VerifierType: verifiers.ETH_ADDRESS,
			},
		},
	}, nil
}

func (h *approveHandler) decodeTransferCall(ctx context.Context, encodedCall []byte) (*TransferWithApprovalParams, error) {
	transferWithApproval := h.noto.contractABI.Functions()["transferWithApproval"]
	if transferWithApproval == nil {
		return nil, i18n.NewError(ctx, msgs.MsgUnknownFunction, "transferWithApproval")
	}
	paramsJSON, err := h.decodeFunctionParams(ctx, transferWithApproval, encodedCall)
	if err != nil {
		return nil, err
	}
	var params TransferWithApprovalParams
	err = json.Unmarshal(paramsJSON, &params)
	return &params, err
}

func (h *approveHandler) decodeFunctionParams(ctx context.Context, functionABI *abi.Entry, encodedCall []byte) ([]byte, error) {
	callData, err := functionABI.DecodeCallDataCtx(ctx, encodedCall)
	if err != nil {
		return nil, err
	}
	return tktypes.StandardABISerializer().SerializeJSON(callData)
}

func (h *approveHandler) transferHash(ctx context.Context, tx *types.ParsedTransaction, params *types.ApproveParams) (ethtypes.HexBytes0xPrefix, error) {
	transferParams, err := h.decodeTransferCall(ctx, params.Call)
	if err != nil {
		return nil, err
	}
	return h.noto.encodeTransferMasked(ctx,
		tx.ContractAddress,
		transferParams.Inputs,
		transferParams.Outputs,
		transferParams.Data)
}

func (h *approveHandler) Assemble(ctx context.Context, tx *types.ParsedTransaction, req *prototk.AssembleTransactionRequest) (*prototk.AssembleTransactionResponse, error) {
	params := tx.Params.(*types.ApproveParams)
	transferHash, err := h.transferHash(ctx, tx, params)
	if err != nil {
		return nil, err
	}

	return &prototk.AssembleTransactionResponse{
		AssemblyResult: prototk.AssembleTransactionResponse_OK,
		AssembledTransaction: &prototk.AssembledTransaction{
			InputStates:  []*prototk.StateRef{},
			OutputStates: []*prototk.NewState{},
		},
		AttestationPlan: []*prototk.AttestationRequest{
			// Sender confirms the initial request with a signature
			{
				Name:            "sender",
				AttestationType: prototk.AttestationType_SIGN,
				Algorithm:       algorithms.ECDSA_SECP256K1,
				VerifierType:    verifiers.ETH_ADDRESS,
				PayloadType:     signpayloads.OPAQUE_TO_RSV,
				Payload:         transferHash,
				Parties:         []string{req.Transaction.From},
			},
			// Notary will endorse the assembled transaction (by submitting to the ledger)
			{
				Name:            "notary",
				AttestationType: prototk.AttestationType_ENDORSE,
				Algorithm:       algorithms.ECDSA_SECP256K1,
				VerifierType:    verifiers.ETH_ADDRESS,
				Parties:         []string{tx.DomainConfig.NotaryLookup},
			},
		},
	}, nil
}

func (h *approveHandler) Endorse(ctx context.Context, tx *types.ParsedTransaction, req *prototk.EndorseTransactionRequest) (*prototk.EndorseTransactionResponse, error) {
	params := tx.Params.(*types.ApproveParams)
	transferHash, err := h.transferHash(ctx, tx, params)
	if err != nil {
		return nil, err
	}
	if err := h.noto.validateApprovalSignature(ctx, req, transferHash); err != nil {
		return nil, err
	}
	return &prototk.EndorseTransactionResponse{
		EndorsementResult: prototk.EndorseTransactionResponse_ENDORSER_SUBMIT,
	}, nil
}

func (h *approveHandler) Prepare(ctx context.Context, tx *types.ParsedTransaction, req *prototk.PrepareTransactionRequest) (*prototk.PrepareTransactionResponse, error) {
	params := tx.Params.(*types.ApproveParams)
	transferHash, err := h.transferHash(ctx, tx, params)
	if err != nil {
		return nil, err
	}
	signature := domain.FindAttestation("sender", req.AttestationResult)
	if signature == nil {
		return nil, i18n.NewError(ctx, msgs.MsgAttestationNotFound, "sender")
	}

	data, err := h.noto.encodeTransactionData(ctx, req.Transaction)
	if err != nil {
		return nil, err
	}
	approveParams := map[string]interface{}{
		"delegate":  params.Delegate,
		"txhash":    transferHash,
		"signature": ethtypes.HexBytes0xPrefix(signature.Payload),
		"data":      data,
	}
	paramsJSON, err := json.Marshal(approveParams)
	if err != nil {
		return nil, err
	}
	functionJSON, err := json.Marshal(h.noto.contractABI.Functions()["approveTransfer"])
	if err != nil {
		return nil, err
	}

	return &prototk.PrepareTransactionResponse{
		Transaction: &prototk.BaseLedgerTransaction{
			FunctionAbiJson: string(functionJSON),
			ParamsJson:      string(paramsJSON),
		},
	}, nil
}
