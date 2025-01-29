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
	"encoding/json"
	"slices"
	"strings"

	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/kaleido-io/paladin/domains/zeto/internal/msgs"
	"github.com/kaleido-io/paladin/domains/zeto/internal/zeto/common"
	corepb "github.com/kaleido-io/paladin/domains/zeto/pkg/proto"
	"github.com/kaleido-io/paladin/domains/zeto/pkg/types"
	"github.com/kaleido-io/paladin/domains/zeto/pkg/zetosigner/zetosignerapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/domain"
	"github.com/kaleido-io/paladin/toolkit/pkg/prototk"
	pb "github.com/kaleido-io/paladin/toolkit/pkg/prototk"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"google.golang.org/protobuf/proto"
)

type lockHandler struct {
	zeto *Zeto
}

var lockABI = &abi.Entry{
	Type: abi.Function,
	Name: "lock",
	Inputs: abi.ParameterArray{
		{Name: "inputs", Type: "uint256[]"},
		{Name: "outputs", Type: "uint256[]"},
		{Name: "lockedOutputs", Type: "uint256[]"},
		{Name: "proof", Type: "tuple", InternalType: "struct Commonlib.Proof", Components: common.ProofComponents},
		{Name: "delegate", Type: "address"},
		{Name: "data", Type: "bytes"},
	},
}

var lockABI_nullifiers = &abi.Entry{
	Type: abi.Function,
	Name: "lock",
	Inputs: abi.ParameterArray{
		{Name: "inputs", Type: "uint256[]"},
		{Name: "outputs", Type: "uint256[]"},
		{Name: "lockedOutputs", Type: "uint256[]"},
		{Name: "root", Type: "uint256"},
		{Name: "proof", Type: "tuple", InternalType: "struct Commonlib.Proof", Components: common.ProofComponents},
		{Name: "delegate", Type: "address"},
		{Name: "data", Type: "bytes"},
	},
}

func (h *lockHandler) ValidateParams(ctx context.Context, config *types.DomainInstanceConfig, params string) (interface{}, error) {
	var lockParams types.LockParams
	if err := json.Unmarshal([]byte(params), &lockParams); err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorUnmarshalLockProofParams, err)
	}
	if lockParams.Amount == nil {
		return nil, i18n.NewError(ctx, msgs.MsgNoParamAmount, 0)
	}
	if lockParams.Amount.Int().Sign() != 1 {
		return nil, i18n.NewError(ctx, msgs.MsgParamTotalAmountInRange)
	}
	if lockParams.Amount.Int().Cmp(MAX_TRANSFER_AMOUNT) >= 0 {
		return nil, i18n.NewError(ctx, msgs.MsgParamTotalAmountInRange)
	}
	return &lockParams, nil
}

func (h *lockHandler) Init(ctx context.Context, tx *types.ParsedTransaction, req *prototk.InitTransactionRequest) (*prototk.InitTransactionResponse, error) {
	return &prototk.InitTransactionResponse{
		RequiredVerifiers: []*prototk.ResolveVerifierRequest{
			{
				Lookup:       tx.Transaction.From,
				Algorithm:    h.zeto.getAlgoZetoSnarkBJJ(),
				VerifierType: zetosignerapi.IDEN3_PUBKEY_BABYJUBJUB_COMPRESSED_0X,
			},
		},
	}, nil
}

func (h *lockHandler) Assemble(ctx context.Context, tx *types.ParsedTransaction, req *prototk.AssembleTransactionRequest) (*prototk.AssembleTransactionResponse, error) {
	params := tx.Params.(*types.LockParams)
	resolvedSender := domain.FindVerifier(tx.Transaction.From, h.zeto.getAlgoZetoSnarkBJJ(), zetosignerapi.IDEN3_PUBKEY_BABYJUBJUB_COMPRESSED_0X, req.ResolvedVerifiers)
	if resolvedSender == nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorResolveVerifier, tx.Transaction.From)
	}

	useNullifiers := common.IsNullifiersToken(tx.DomainConfig.TokenName)
	inputCoins, inputStates, _, remainder, err := h.zeto.buildInputsForExpectedTotal(ctx, useNullifiers, req.StateQueryContext, resolvedSender.Verifier, params.Amount.Int())
	if err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorPrepTxInputs, err)
	}

	var outputCoins []*types.ZetoCoin
	var outputStates []*pb.NewState
	if remainder.Sign() > 0 {
		remainderOutputEntries := []*types.TransferParamEntry{
			{
				To:     tx.Transaction.From, // remainder outputs are for the sender themselves
				Amount: tktypes.Uint64ToUint256(remainder.Uint64()),
			},
		}
		outputCoins, outputStates, err = h.zeto.prepareOutputsForTransfer(ctx, useNullifiers, remainderOutputEntries, req.ResolvedVerifiers)
		if err != nil {
			return nil, i18n.NewError(ctx, msgs.MsgErrorPrepTxOutputs, err)
		}
	}

	lockedOutputEntries := []*types.TransferParamEntry{
		{
			To:     tx.Transaction.From, // locked outputs are for the sender themselves
			Amount: params.Amount,
		},
	}
	lockedOutputCoins, lockedOutputStates, err := h.zeto.prepareOutputsForTransfer(ctx, useNullifiers, lockedOutputEntries, req.ResolvedVerifiers)
	if err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorPrepTxOutputs, err)
	}

	contractAddress, err := tktypes.ParseEthAddress(req.Transaction.ContractInfo.ContractAddress)
	if err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorDecodeContractAddress, err)
	}
	allOutputCoins := slices.Concat(outputCoins, lockedOutputCoins)
	circuitId := tx.DomainConfig.Circuits["transfer"] // use the transfer circuit for locking proofs
	payloadBytes, err := formatTransferProvingRequest(ctx, h.zeto, inputCoins, allOutputCoins, circuitId, tx.DomainConfig.TokenName, req.StateQueryContext, contractAddress)
	if err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorFormatProvingReq, err)
	}

	return &prototk.AssembleTransactionResponse{
		AssemblyResult: prototk.AssembleTransactionResponse_OK,
		AssembledTransaction: &prototk.AssembledTransaction{
			InputStates:  inputStates,
			OutputStates: outputStates,
			InfoStates:   lockedOutputStates, // making use of the InfoStates field to store the locked outputs
		},
		AttestationPlan: []*prototk.AttestationRequest{
			{
				Name:            "sender",
				AttestationType: pb.AttestationType_SIGN,
				Algorithm:       h.zeto.getAlgoZetoSnarkBJJ(),
				VerifierType:    zetosignerapi.IDEN3_PUBKEY_BABYJUBJUB_COMPRESSED_0X,
				PayloadType:     zetosignerapi.PAYLOAD_DOMAIN_ZETO_SNARK,
				Payload:         payloadBytes,
				Parties:         []string{tx.Transaction.From},
			},
		},
	}, nil
}

func (h *lockHandler) Endorse(ctx context.Context, tx *types.ParsedTransaction, req *prototk.EndorseTransactionRequest) (*prototk.EndorseTransactionResponse, error) {
	return nil, nil
}

func (h *lockHandler) Prepare(ctx context.Context, tx *types.ParsedTransaction, req *prototk.PrepareTransactionRequest) (*prototk.PrepareTransactionResponse, error) {
	var proofRes corepb.ProvingResponse
	result := domain.FindAttestation("sender", req.AttestationResult)
	if result == nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorFindSenderAttestation)
	}
	if err := proto.Unmarshal(result.Payload, &proofRes); err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorUnmarshalProvingRes, err)
	}

	inputSize := common.GetInputSize(len(req.InputStates))
	inputs, err := utxosFromInputStates(ctx, h.zeto, req.InputStates, inputSize)
	if err != nil {
		return nil, err
	}
	outputs, err := utxosFromOutputStates(ctx, h.zeto, req.OutputStates, inputSize)
	if err != nil {
		return nil, err
	}
	lockedOutputs, err := utxosFromOutputStates(ctx, h.zeto, req.InfoStates, inputSize)
	if err != nil {
		return nil, err
	}

	data, err := encodeTransactionData(ctx, req.Transaction)
	if err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorEncodeTxData, err)
	}
	params := map[string]any{
		"inputs":        inputs,
		"outputs":       outputs,
		"lockedOutputs": lockedOutputs,
		"proof":         encodeProof(proofRes.Proof),
		"data":          data,
	}
	transferFunction := getTransferABI(tx.DomainConfig.TokenName)
	if common.IsNullifiersToken(tx.DomainConfig.TokenName) {
		delete(params, "inputs")
		params["nullifiers"] = strings.Split(proofRes.PublicInputs["nullifiers"], ",")
		params["root"] = proofRes.PublicInputs["root"]
	}
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorMarshalPrepedParams, err)
	}
	functionJSON, err := json.Marshal(transferFunction)
	if err != nil {
		return nil, err
	}

	return &pb.PrepareTransactionResponse{
		Transaction: &pb.PreparedTransaction{
			FunctionAbiJson: string(functionJSON),
			ParamsJson:      string(paramsJSON),
		},
	}, nil
}

// func (h *lockHandler) loadCoins(ctx context.Context, ids []any, stateQueryContext string) ([]*types.ZetoCoin, error) {
// 	inputIDs := make([]any, 0, len(ids))
// 	for _, input := range ids {
// 		parsed, err := tktypes.ParseHexUint256(ctx, input.(string))
// 		if err != nil {
// 			return nil, err
// 		}
// 		if !parsed.NilOrZero() {
// 			inputIDs = append(inputIDs, parsed)
// 		}
// 	}

// 	queryBuilder := query.NewQueryBuilder().In(".id", inputIDs)
// 	inputStates, err := h.zeto.findAvailableStates(ctx, false, stateQueryContext, queryBuilder.Query().String())
// 	if err != nil {
// 		return nil, err
// 	}
// 	if len(inputStates) != len(inputIDs) {
// 		return nil, i18n.NewError(ctx, msgs.MsgErrorParseInputStates)
// 	}

// 	inputCoins := make([]*types.ZetoCoin, len(inputStates))
// 	for i, state := range inputStates {
// 		err := json.Unmarshal([]byte(state.DataJson), &inputCoins[i])
// 		if err != nil {
// 			return nil, err
// 		}
// 	}
// 	return inputCoins, nil
// }
