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
	"sync"
	"time"

	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/kaleido-io/paladin/config/pkg/confutil"
	"github.com/kaleido-io/paladin/config/pkg/pldconf"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/msgs"
	"github.com/kaleido-io/paladin/core/internal/privatetxnmgr/ptmgrtypes"
	"github.com/kaleido-io/paladin/core/internal/privatetxnmgr/syncpoints"
	"github.com/kaleido-io/paladin/core/internal/statedistribution"

	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/pldapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

type SequencerState string

const (
	// brand new sequencer
	SequencerStateNew SequencerState = "new"
	// sequencer running normally
	SequencerStateRunning SequencerState = "running"
	// sequencer is blocked and waiting for precondition to be fulfilled, e.g. pre-req tx blocking current stage
	SequencerStateWaiting SequencerState = "waiting"
	// transactions managed by an sequencer stuck in the same state
	SequencerStateStale SequencerState = "stale"
	// no transactions in a specific sequencer
	SequencerStateIdle SequencerState = "idle"
	// sequencer is paused
	SequencerStatePaused SequencerState = "paused"
	// sequencer is stopped
	SequencerStateStopped SequencerState = "stopped"
)

var AllSequencerStates = []string{
	string(SequencerStateNew),
	string(SequencerStateRunning),
	string(SequencerStateWaiting),
	string(SequencerStateStale),
	string(SequencerStateIdle),
	string(SequencerStatePaused),
	string(SequencerStateStopped),
}

type Sequencer struct {
	ctx                     context.Context
	persistenceRetryTimeout time.Duration

	// each sequencer has its own go routine
	initiated    time.Time     // when sequencer is created
	evalInterval time.Duration // between how long the sequencer will do an evaluation to check & remove transactions that missed events

	maxConcurrentProcess        int
	incompleteTxProcessMapMutex sync.Mutex
	incompleteTxSProcessMap     map[string]ptmgrtypes.TxProcessor // a map of all known transactions that are not completed

	processedTxIDs    map[string]bool // an internal record of completed transactions to handle persistence delays that causes reprocessing
	sequencerLoopDone chan struct{}

	// input channels
	orchestrationEvalRequestChan chan bool
	stopProcess                  chan bool // a channel to tell the current sequencer to stop processing all events and mark itself as to be deleted

	// Metrics provided for fairness control in the controller
	totalCompleted int64 // total number of transaction completed since initiated
	state          SequencerState
	stateEntryTime time.Time // when the sequencer entered the current state

	staleTimeout time.Duration

	pendingEvents chan ptmgrtypes.PrivateTransactionEvent

	contractAddress     tktypes.EthAddress // the contract address managed by the current sequencer
	nodeID              string
	domainAPI           components.DomainSmartContract
	components          components.AllComponents
	endorsementGatherer ptmgrtypes.EndorsementGatherer
	publisher           ptmgrtypes.Publisher
	identityResolver    components.IdentityResolver
	syncPoints          syncpoints.SyncPoints
	stateDistributer    statedistribution.StateDistributer
	transportWriter     ptmgrtypes.TransportWriter
	graph               Graph
	requestTimeout      time.Duration
}

func NewSequencer(
	ctx context.Context,
	nodeID string,
	contractAddress tktypes.EthAddress,
	sequencerConfig *pldconf.PrivateTxManagerSequencerConfig,
	allComponents components.AllComponents,
	domainAPI components.DomainSmartContract,
	endorsementGatherer ptmgrtypes.EndorsementGatherer,
	publisher ptmgrtypes.Publisher,
	syncPoints syncpoints.SyncPoints,
	identityResolver components.IdentityResolver,
	stateDistributer statedistribution.StateDistributer,
	transportWriter ptmgrtypes.TransportWriter,
	requestTimeout time.Duration,
) *Sequencer {

	newSequencer := &Sequencer{
		ctx:                  log.WithLogField(ctx, "role", fmt.Sprintf("sequencer-%s", contractAddress)),
		initiated:            time.Now(),
		contractAddress:      contractAddress,
		evalInterval:         confutil.DurationMin(sequencerConfig.EvaluationInterval, 1*time.Millisecond, *pldconf.PrivateTxManagerDefaults.Sequencer.EvaluationInterval),
		maxConcurrentProcess: confutil.Int(sequencerConfig.MaxConcurrentProcess, *pldconf.PrivateTxManagerDefaults.Sequencer.MaxConcurrentProcess),
		state:                SequencerStateNew,
		stateEntryTime:       time.Now(),

		incompleteTxSProcessMap: make(map[string]ptmgrtypes.TxProcessor),
		persistenceRetryTimeout: confutil.DurationMin(sequencerConfig.PersistenceRetryTimeout, 1*time.Millisecond, *pldconf.PrivateTxManagerDefaults.Sequencer.PersistenceRetryTimeout),

		staleTimeout:                 confutil.DurationMin(sequencerConfig.StaleTimeout, 1*time.Millisecond, *pldconf.PrivateTxManagerDefaults.Sequencer.StaleTimeout),
		processedTxIDs:               make(map[string]bool),
		orchestrationEvalRequestChan: make(chan bool, 1),
		stopProcess:                  make(chan bool, 1),
		pendingEvents:                make(chan ptmgrtypes.PrivateTransactionEvent, *pldconf.PrivateTxManagerDefaults.Sequencer.MaxPendingEvents),
		nodeID:                       nodeID,
		domainAPI:                    domainAPI,
		components:                   allComponents,
		endorsementGatherer:          endorsementGatherer,
		publisher:                    publisher,
		syncPoints:                   syncPoints,
		identityResolver:             identityResolver,
		stateDistributer:             stateDistributer,
		transportWriter:              transportWriter,
		graph:                        NewGraph(),
		requestTimeout:               requestTimeout,
	}

	log.L(ctx).Debugf("NewSequencer for contract address %s created: %+v", newSequencer.contractAddress, newSequencer)

	return newSequencer
}

func (s *Sequencer) abort(err error) {
	log.L(s.ctx).Errorf("Sequencer aborting: %s", err)
	s.stopProcess <- true

}
func (s *Sequencer) getTransactionProcessor(txID string) ptmgrtypes.TxProcessor {
	s.incompleteTxProcessMapMutex.Lock()
	defer s.incompleteTxProcessMapMutex.Unlock()
	transactionProcessor, ok := s.incompleteTxSProcessMap[txID]
	if !ok {
		log.L(s.ctx).Errorf("Transaction processor not found for transaction ID %s", txID)
		return nil
	}
	return transactionProcessor
}

func (s *Sequencer) removeTransactionProcessor(txID string) {
	s.incompleteTxProcessMapMutex.Lock()
	defer s.incompleteTxProcessMapMutex.Unlock()
	delete(s.incompleteTxSProcessMap, txID)
}

func (s *Sequencer) evaluationLoop() {
	// Select from the event channel and process each event on a single thread
	// individual event handlers are responsible for kicking off another go routine if they have
	// long running tasks that are not dependant on the order of events
	// TODO if the channel ever fills up, then we need to be aware that we have potentially missed some events
	// and we need to poll the database for any events that we missed

	ctx := log.WithLogField(s.ctx, "role", fmt.Sprintf("pctm-loop-%s", s.contractAddress))
	log.L(ctx).Infof("Sequencer for contract address %s started evaluation loop based on interval %s", s.contractAddress, s.evalInterval)

	defer close(s.sequencerLoopDone)

	ticker := time.NewTicker(s.evalInterval)
	for {
		// an InFlight
		select {
		case pendingEvent := <-s.pendingEvents:
			s.handleEvent(ctx, pendingEvent)
		case <-s.orchestrationEvalRequestChan:
		case <-ticker.C:
		case <-ctx.Done():
			log.L(ctx).Infof("Sequencer loop exit due to canceled context, it processed %d transaction during its lifetime.", s.totalCompleted)
			return
		case <-s.stopProcess:
			log.L(ctx).Infof("Sequencer loop process stopped, it processed %d transaction during its lifetime.", s.totalCompleted)
			s.state = SequencerStateStopped
			s.stateEntryTime = time.Now()
			// TODO: trigger parent loop for removal
			return
		}
		// TODO while we have woken up, iterate through all transactions in memory and check if any are stale or completed and query the database for any in flight transactions that need to be brought into memory
	}
}

func (s *Sequencer) handleEvent(ctx context.Context, event ptmgrtypes.PrivateTransactionEvent) {
	//For any event that is specific to a single transaction,
	// find (or create) the transaction processor for that transaction
	// and pass the event to it
	transactionID := event.GetTransactionID()
	log.L(ctx).Debugf("Sequencer handling event %T for transaction %s", event, transactionID)

	transactionProcessor := s.getTransactionProcessor(transactionID)
	if transactionProcessor == nil {
		//What has happened here is either:
		// a) we don't know about this transaction yet, which is possible if we have just restarted
		// and not yet completed the initialization from the database but in the interim, we have received
		// a transport message from another node concerning this transaction
		// b) the transaction has been completed and removed from memory
		// in case of (a) we ignore it and rely on the fact that we will send out request for data that we need once
		// we have completed the initialization from the database
		// in case of (b) we ignore it because an event for a completed transaction is redundant.
		// most likely it is a tardy response for something we timed out waiting for and failed or retried successfully
		log.L(ctx).Warnf("Received an event for a transaction that is not in flight %s", transactionID)
		return
	}

	validationError := event.Validate(ctx)
	if validationError != nil {
		log.L(ctx).Errorf("Error validating %T event: %s ", event, validationError.Error())
		//we can't handle this event.  If that leaves a transaction in an incomplete state, then it will eventually resend requests for the data it needs
		return
	}

	/*
		Apply the event to the transaction processor's in memory record of the transaction
		this is expected to be a simple in memory data mapping and therefore is not expected to return any errors
		it must either
			- decide to ignore the event altogether
			- completely apply the the event
			- panic if the event data is partially applied and an unexpected error occurs before it can be completely applied
	*/
	transactionProcessor.ApplyEvent(ctx, event)

	/*
		 	After applying the event to the transaction, we can either a) clean up that transaction ( if we have just learned, from the event that the transaction is complete and needs no further actions)
			or b) perform any necessary actions (e.g. sending requests for signatures, endorsements etc.)
	*/
	if transactionProcessor.IsComplete() {

		s.graph.RemoveTransaction(ctx, transactionID)
		s.removeTransactionProcessor(transactionID)
	} else {

		/*
			Action will perform any necessary actions based on the current state of the transaction.
			This may include sending asynchronous requests for data and/or synchronous analysis of the in memory record of the transaction.
			Action is retry safe and idempotent.
		*/
		transactionProcessor.Action(ctx)
	}

	if transactionProcessor.CoordinatingLocally() && transactionProcessor.ReadyForSequencing() && !transactionProcessor.Dispatched() {
		// we are responsible for coordinating the endorsement flow for this transaction, ensure that it has been added it to the graph
		// NOTE: AddTransaction is idempotent so we don't need to check whether we have already added it
		s.graph.AddTransaction(ctx, transactionProcessor)
	}

	//analyze the graph to see if we can dispatch any transactions
	dispatchableTransactions, err := s.graph.GetDispatchableTransactions(ctx)
	if err != nil {
		//If the graph can't give us an answer without an error then we have no confidence that we are in possession of a valid
		// graph of transactions that can successfully be dispatched so only option here is to abandon everything we have in-memory for this contract
		// and start again
		log.L(ctx).Errorf("Error getting dispatchable transactions: %s", err)
		s.abort(err)
		return
	}
	if len(dispatchableTransactions) == 0 {
		log.L(ctx).Debug("No dispatchable transactions")
		return
	}
	err = s.DispatchTransactions(ctx, dispatchableTransactions)
	if err != nil {
		log.L(ctx).Errorf("Error dispatching transaction: %s", err)
		// assuming this is a transient error with e.g. network or the DB, then we will try again next time round the loop
		return
	}

	//DispatchTransactions is a persistence point so we can remove the transactions from our graph now that they are dispatched
	s.graph.RemoveTransactions(ctx, dispatchableTransactions)

}

func (s *Sequencer) ProcessNewTransaction(ctx context.Context, tx *components.PrivateTransaction) (queued bool) {
	s.incompleteTxProcessMapMutex.Lock()
	defer s.incompleteTxProcessMapMutex.Unlock()
	if s.incompleteTxSProcessMap[tx.ID.String()] == nil {
		if len(s.incompleteTxSProcessMap) >= s.maxConcurrentProcess {
			// TODO: decide how this map is managed, it shouldn't track the entire lifecycle
			// tx processing pool is full, queue the item
			return true
		} else {
			s.incompleteTxSProcessMap[tx.ID.String()] = NewPaladinTransactionProcessor(ctx, tx, s.nodeID, s.components, s.domainAPI, s.publisher, s.endorsementGatherer, s.identityResolver, s.syncPoints, s.transportWriter, s.requestTimeout)
		}
		s.pendingEvents <- &ptmgrtypes.TransactionSubmittedEvent{
			PrivateTransactionEventBase: ptmgrtypes.PrivateTransactionEventBase{TransactionID: tx.ID.String()},
		}
	}
	return false
}

func (s *Sequencer) ProcessInFlightTransaction(ctx context.Context, tx *components.PrivateTransaction) (queued bool) {
	log.L(ctx).Infof("Processing in flight transaction %s", tx.ID)
	//a transaction that already has had some processing done on it
	// currently the only case this can happen is a transaction delegated from another node
	// but maybe in future, inflight transactions being coordinated locally could be swapped out of memory when they are blocked and/or if we are at max concurrency
	s.incompleteTxProcessMapMutex.Lock()
	defer s.incompleteTxProcessMapMutex.Unlock()
	_, alreadyInMemory := s.incompleteTxSProcessMap[tx.ID.String()]
	if alreadyInMemory {
		log.L(ctx).Warnf("Transaction %s already in memory. Ignoring", tx.ID)
		return false
	}
	if s.incompleteTxSProcessMap[tx.ID.String()] == nil {
		if len(s.incompleteTxSProcessMap) >= s.maxConcurrentProcess {
			// TODO: decide how this map is managed, it shouldn't track the entire lifecycle
			// tx processing pool is full, queue the item
			return true
		} else {
			s.incompleteTxSProcessMap[tx.ID.String()] = NewPaladinTransactionProcessor(ctx, tx, s.nodeID, s.components, s.domainAPI, s.publisher, s.endorsementGatherer, s.identityResolver, s.syncPoints, s.transportWriter, s.requestTimeout)
		}
		s.pendingEvents <- &ptmgrtypes.TransactionSwappedInEvent{
			PrivateTransactionEventBase: ptmgrtypes.PrivateTransactionEventBase{TransactionID: tx.ID.String()},
		}
	}
	return false
}

func (s *Sequencer) HandleEvent(ctx context.Context, event ptmgrtypes.PrivateTransactionEvent) {
	s.pendingEvents <- event
}

func (s *Sequencer) Start(c context.Context) (done <-chan struct{}, err error) {
	s.syncPoints.Start()
	s.sequencerLoopDone = make(chan struct{})
	go s.evaluationLoop()
	s.TriggerSequencerEvaluation()
	return s.sequencerLoopDone, nil
}

// Stop the InFlight transaction process.
func (s *Sequencer) Stop() {
	// try to send an item in `stopProcess` channel, which has a buffer of 1
	// if it already has an item in the channel, this function does nothing
	select {
	case s.stopProcess <- true:
	default:
	}

}

func (s *Sequencer) TriggerSequencerEvaluation() {
	// try to send an item in `processNow` channel, which has a buffer of 1
	// if it already has an item in the channel, this function does nothing
	select {
	case s.orchestrationEvalRequestChan <- true:
	default:
	}
}

func (s *Sequencer) GetTxStatus(ctx context.Context, txID string) (status components.PrivateTxStatus, err error) {
	//TODO This is primarily here to help with testing for now
	// this needs to be revisited ASAP as part of a holisitic review of the persistence model
	s.incompleteTxProcessMapMutex.Lock()
	defer s.incompleteTxProcessMapMutex.Unlock()
	if txProc, ok := s.incompleteTxSProcessMap[txID]; ok {
		return txProc.GetTxStatus(ctx)
	}
	//TODO should be possible to query the status of a transaction that is not inflight
	return components.PrivateTxStatus{}, i18n.NewError(ctx, msgs.MsgPrivateTxManagerInternalError, "Transaction not found")
}

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

			preparedTransaction, err := txProcessor.PrepareTransaction(ctx)
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

	err := s.syncPoints.PersistDispatchBatch(ctx, s.contractAddress, dispatchBatch, stateDistributions)
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
