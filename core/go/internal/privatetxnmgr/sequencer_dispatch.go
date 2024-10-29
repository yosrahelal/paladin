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

package privatetxnmgr

import (
	"context"
	"fmt"

	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/msgs"
	"github.com/kaleido-io/paladin/core/internal/privatetxnmgr/ptmgrtypes"
	"github.com/kaleido-io/paladin/core/internal/privatetxnmgr/syncpoints"
	"github.com/kaleido-io/paladin/core/internal/statedistribution"

	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/pldapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

// synchronously prepare and dispatch all given transactions to their associated signing address
func (s *Sequencer) DispatchTransactions(ctx context.Context, dispatchableTransactions ptmgrtypes.DispatchableTransactions) error {
	log.L(ctx).Debug("DispatchTransactions")
	//prepare all transactions then dispatch them

	// array of sequences with space for one per signing address
	// dispatchableTransactions is a map of signing address to transaction IDs so we can group by signing address
	dispatchBatch := &syncpoints.DispatchBatch{
		DispatchSequences: make([]*syncpoints.DispatchSequence, 0, len(dispatchableTransactions)),
	}

	stateDistributions := make([]*statedistribution.StateDistribution, 0)

	completed := false // and include whether we committed the DB transaction or not
	for signingAddress, transactionIDs := range dispatchableTransactions {
		log.L(ctx).Debugf("DispatchTransactions: %d transactions for signingAddress %s", len(transactionIDs), signingAddress)

		preparedTransactions := make([]*components.PrivateTransaction, len(transactionIDs))

		sequence := &syncpoints.DispatchSequence{
			PrivateTransactionDispatches: make([]*syncpoints.DispatchPersisted, len(transactionIDs)),
		}

		for i, transactionID := range transactionIDs {
			// prepare all transactions for the given transaction IDs

			sequence.PrivateTransactionDispatches[i] = &syncpoints.DispatchPersisted{
				PrivateTransactionID: transactionID,
			}

			txProcessor := s.getTransactionProcessor(transactionID)
			if txProcessor == nil {
				//TODO currently assume that all the transactions are in flight and in memory
				// need to reload from database if not in memory
				panic("Transaction not found")
			}

			// If we don't have a signing key for the TX at this point, we use our randomly assigned one
			// TODO: Rotation
			preparedTransaction, err := txProcessor.PrepareTransaction(ctx, s.defaultSigner)
			if err != nil {
				log.L(ctx).Errorf("Error preparing transaction: %s", err)
				//TODO this is a really bad time to be getting an error.  need to think carefully about how to handle this
				return err
			}
			if preparedTransaction.PreparedPublicTransaction == nil {
				// TODO: add handling
				panic("private transactions triggering private transactions currently supported only in testbed")
			}
			preparedTransactions[i] = preparedTransaction

			stateDistributions = append(stateDistributions, txProcessor.GetStateDistributions(ctx)...)
		}

		preparedTransactionPayloads := make([]*pldapi.TransactionInput, len(preparedTransactions))

		for j, preparedTransaction := range preparedTransactions {
			preparedTransactionPayloads[j] = preparedTransaction.PreparedPublicTransaction
		}

		//Now we have the payloads, we can prepare the submission
		publicTransactionEngine := s.components.PublicTxManager()

		signers := make([]string, len(preparedTransactions))
		for i, pt := range preparedTransactions {
			unqualifiedSigner, err := tktypes.PrivateIdentityLocator(pt.Signer).Identity(ctx)
			if err != nil {
				errorMessage := fmt.Sprintf("failed to parse lookup key for signer %s : %s", pt.Signer, err)
				log.L(ctx).Error(errorMessage)
				return i18n.WrapError(ctx, err, msgs.MsgPrivateTxManagerInternalError, errorMessage)
			}

			signers[i] = unqualifiedSigner
		}
		keyMgr := s.components.KeyManager()
		resolvedAddrs, err := keyMgr.ResolveEthAddressBatchNewDatabaseTX(ctx, signers)
		if err != nil {
			return err
		}

		publicTXs := make([]*components.PublicTxSubmission, len(preparedTransactions))
		for i, pt := range preparedTransactions {
			log.L(ctx).Debugf("DispatchTransactions: creating PublicTxSubmission from %s", pt.Signer)
			publicTXs[i] = &components.PublicTxSubmission{
				Bindings: []*components.PaladinTXReference{{TransactionID: pt.ID, TransactionType: pldapi.TransactionTypePrivate.Enum()}},
				PublicTxInput: pldapi.PublicTxInput{
					From:            resolvedAddrs[i],
					To:              &s.contractAddress,
					PublicTxOptions: pldapi.PublicTxOptions{}, // TODO: Consider propagation from paladin transaction input
				},
			}

			// TODO: This aligning with submission in public Tx manage
			data, err := pt.PreparedPublicTransaction.ABI[0].EncodeCallDataJSONCtx(ctx, pt.PreparedPublicTransaction.Data)
			if err != nil {
				return err
			}
			publicTXs[i].Data = tktypes.HexBytes(data)
		}
		pubBatch, err := publicTransactionEngine.PrepareSubmissionBatch(ctx, publicTXs)
		if err != nil {
			return i18n.WrapError(ctx, err, msgs.MsgPrivTxMgrPublicTxFail)
		}
		// Must make sure from this point we return the nonces
		sequence.PublicTxBatch = pubBatch
		defer func() {
			pubBatch.Completed(ctx, completed)
		}()
		if len(pubBatch.Rejected()) > 0 {
			// We do not handle partial success - roll everything back
			return i18n.WrapError(ctx, pubBatch.Rejected()[0].RejectedError(), msgs.MsgPrivTxMgrPublicTxFail)
		}

		dispatchBatch.DispatchSequences = append(dispatchBatch.DispatchSequences, sequence)
	}

	// TODO: per notes in endorsementGatherer determine if that's the right place to hold the domain context
	err := s.syncPoints.PersistDispatchBatch(s.endorsementGatherer.DomainContext(), s.contractAddress, dispatchBatch, stateDistributions)
	if err != nil {
		log.L(ctx).Errorf("Error persisting batch: %s", err)
		return err
	}
	completed = true
	for signingAddress, sequence := range dispatchableTransactions {
		for _, privateTransactionID := range sequence {
			s.publisher.PublishTransactionDispatchedEvent(ctx, privateTransactionID, uint64(0) /*TODO*/, signingAddress)
		}
	}
	//now that the DB write has been persisted, we can trigger the in-memory state distribution
	s.stateDistributer.DistributeStates(ctx, stateDistributions)

	return nil

}
