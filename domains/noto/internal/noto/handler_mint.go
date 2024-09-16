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
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/kaleido-io/paladin/domains/noto/internal/msgs"
	"github.com/kaleido-io/paladin/domains/noto/pkg/types"
	"github.com/kaleido-io/paladin/toolkit/pkg/algorithms"
	"github.com/kaleido-io/paladin/toolkit/pkg/domain"
	pb "github.com/kaleido-io/paladin/toolkit/pkg/prototk"
)

type mintHandler struct {
	noto *Noto
}

func (h *mintHandler) ValidateParams(ctx context.Context, params string) (interface{}, error) {
	var mintParams types.MintParams
	if err := json.Unmarshal([]byte(params), &mintParams); err != nil {
		return nil, err
	}
	if mintParams.To == "" {
		return nil, i18n.NewError(ctx, msgs.MsgParameterRequired, "to")
	}
	if mintParams.Amount.BigInt().Sign() != 1 {
		return nil, i18n.NewError(ctx, msgs.MsgParameterGreaterThanZero, "amount")
	}
	return &mintParams, nil
}

func (h *mintHandler) Init(ctx context.Context, tx *types.ParsedTransaction, req *pb.InitTransactionRequest) (*pb.InitTransactionResponse, error) {
	params := tx.Params.(*types.MintParams)

	if req.Transaction.From != tx.DomainConfig.NotaryLookup {
		return nil, i18n.NewError(ctx, msgs.MsgMintOnlyNotary)
	}
	return &pb.InitTransactionResponse{
		RequiredVerifiers: []*pb.ResolveVerifierRequest{
			{
				Lookup:    tx.DomainConfig.NotaryLookup,
				Algorithm: algorithms.ECDSA_SECP256K1_PLAINBYTES,
			},
			{
				Lookup:    params.To,
				Algorithm: algorithms.ECDSA_SECP256K1_PLAINBYTES,
			},
		},
	}, nil
}

func (h *mintHandler) Assemble(ctx context.Context, tx *types.ParsedTransaction, req *pb.AssembleTransactionRequest) (*pb.AssembleTransactionResponse, error) {
	params := tx.Params.(*types.MintParams)

	notary := domain.FindVerifier(tx.DomainConfig.NotaryLookup, algorithms.ECDSA_SECP256K1_PLAINBYTES, req.ResolvedVerifiers)
	if notary == nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorVerifyingAddress, "notary")
	}
	if notary.Verifier != tx.DomainConfig.NotaryAddress {
		return nil, i18n.NewError(ctx, msgs.MsgNotaryUnexpectedAddress, tx.DomainConfig.NotaryAddress, notary.Verifier)
	}
	to := domain.FindVerifier(params.To, algorithms.ECDSA_SECP256K1_PLAINBYTES, req.ResolvedVerifiers)
	if to == nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorVerifyingAddress, "to")
	}
	toAddress, err := ethtypes.NewAddress(to.Verifier)
	if err != nil {
		return nil, err
	}

	_, outputStates, err := h.noto.prepareOutputs(*toAddress, params.Amount)
	if err != nil {
		return nil, err
	}

	return &pb.AssembleTransactionResponse{
		AssemblyResult: pb.AssembleTransactionResponse_OK,
		AssembledTransaction: &pb.AssembledTransaction{
			OutputStates: outputStates,
		},
		AttestationPlan: []*pb.AttestationRequest{
			// Notary will endorse the assembled transaction (by submitting to the ledger)
			// Note no  additional attestation using req.Transaction.From, because it is guaranteed to be the notary
			{
				Name:            "notary",
				AttestationType: pb.AttestationType_ENDORSE,
				Algorithm:       algorithms.ECDSA_SECP256K1_PLAINBYTES,
				Parties:         []string{tx.DomainConfig.NotaryLookup},
			},
		},
	}, nil
}

func (h *mintHandler) validateAmounts(ctx context.Context, params *types.MintParams, coins *gatheredCoins) error {
	if len(coins.inCoins) > 0 {
		return i18n.NewError(ctx, msgs.MsgInvalidInputs, "mint", coins.inCoins)
	}
	if coins.outTotal.Cmp(params.Amount.BigInt()) != 0 {
		return i18n.NewError(ctx, msgs.MsgInvalidAmount, "mint", params.Amount.BigInt().Text(10), coins.outTotal.Text(10))
	}
	return nil
}

func (h *mintHandler) Endorse(ctx context.Context, tx *types.ParsedTransaction, req *pb.EndorseTransactionRequest) (*pb.EndorseTransactionResponse, error) {
	params := tx.Params.(*types.MintParams)
	coins, err := h.noto.gatherCoins(ctx, req.Inputs, req.Outputs)
	if err != nil {
		return nil, err
	}
	if err := h.validateAmounts(ctx, params, coins); err != nil {
		return nil, err
	}
	return &pb.EndorseTransactionResponse{
		EndorsementResult: pb.EndorseTransactionResponse_ENDORSER_SUBMIT,
	}, nil
}

func (h *mintHandler) Prepare(ctx context.Context, tx *types.ParsedTransaction, req *pb.PrepareTransactionRequest) (*pb.PrepareTransactionResponse, error) {
	outputs := make([]string, len(req.OutputStates))
	for i, state := range req.OutputStates {
		outputs[i] = state.Id
	}

	params := map[string]interface{}{
		"outputs":   outputs,
		"signature": "0x", // no signature, because requester AND submitter are always the notary
		"data":      req.Transaction.TransactionId,
	}
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	functionJSON, err := json.Marshal(h.noto.contractABI.Functions()["mint"])
	if err != nil {
		return nil, err
	}

	return &pb.PrepareTransactionResponse{
		Transaction: &pb.BaseLedgerTransaction{
			FunctionAbiJson: string(functionJSON),
			ParamsJson:      string(paramsJSON),
		},
	}, nil
}
