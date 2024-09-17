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
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/engine/enginespi"
	"github.com/kaleido-io/paladin/core/internal/msgs"
	"github.com/kaleido-io/paladin/core/internal/privatetxnmgr/privatetxnstore"
	"github.com/kaleido-io/paladin/core/internal/privatetxnmgr/ptmgrtypes"
	"github.com/kaleido-io/paladin/toolkit/pkg/confutil"

	"github.com/kaleido-io/paladin/toolkit/pkg/log"
)

// Orchestrator orchestrates transaction processing within a specific private preserving contract
// Key responsibilities:
// - Fairness control for transaction processing within a contract
// - Apply ordering constraints between transactions
// - Detect and initiating stage processing of each transactions through 2 ways:
//    a. events through a buffered channel for back-pressure to drive the pace
//    b. fetching from DB as a fallback mechanism when events are missed

// configurations
const (
	OrchestratorSection = "orchestrator"
)

type OrchestratorConfig struct {
	MaxConcurrentProcess    *int    `yaml:"maxConcurrentProcess,omitempty"`
	MaxPendingEvents        *int    `yaml:"maxPendingEvents,omitempty"`
	StageRetry              *string `yaml:"stageRetry,omitempty"`
	EvaluationInterval      *string `yaml:"evalInterval,omitempty"`
	PersistenceRetryTimeout *string `yaml:"persistenceRetryTimeout,omitempty"`
	StaleTimeout            *string `yaml:"staleTimeout,omitempty"`
}

// metrics

// Gauge metrics

// Counter metrics

// Histograms metrics

type OrchestratorState string

const (
	// brand new orchestrator
	OrchestratorStateNew OrchestratorState = "new"
	// orchestrator running normally
	OrchestratorStateRunning OrchestratorState = "running"
	// orchestrator is blocked and waiting for precondition to be fulfilled, e.g. pre-req tx blocking current stage
	OrchestratorStateWaiting OrchestratorState = "waiting"
	// transactions managed by an orchestrator stuck in the same state
	OrchestratorStateStale OrchestratorState = "stale"
	// no transactions in a specific orchestrator
	OrchestratorStateIdle OrchestratorState = "idle"
	// orchestrator is paused
	OrchestratorStatePaused OrchestratorState = "paused"
	// orchestrator is stopped
	OrchestratorStateStopped OrchestratorState = "stopped"
)

var AllOrchestratorStates = []string{
	string(OrchestratorStateNew),
	string(OrchestratorStateRunning),
	string(OrchestratorStateWaiting),
	string(OrchestratorStateStale),
	string(OrchestratorStateIdle),
	string(OrchestratorStatePaused),
	string(OrchestratorStateStopped),
}

type Orchestrator struct {
	ctx                     context.Context
	stageRetryTimeout       time.Duration
	persistenceRetryTimeout time.Duration

	// each orchestrator has its own go routine
	initiated    time.Time     // when orchestrator is created
	evalInterval time.Duration // between how long the orchestrator will do an evaluation to check & remove transactions that missed events

	maxConcurrentProcess        int
	incompleteTxProcessMapMutex sync.Mutex
	incompleteTxSProcessMap     map[string]ptmgrtypes.TxProcessor // a map of all known transactions that are not completed

	processedTxIDs       map[string]bool // an internal record of completed transactions to handle persistence delays that causes reprocessing
	orchestratorLoopDone chan struct{}

	// input channels
	orchestrationEvalRequestChan chan bool
	stopProcess                  chan bool // a channel to tell the current orchestrator to stop processing all events and mark itself as to be deleted

	// Metrics provided for fairness control in the controler
	totalCompleted int64 // total number of transaction completed since initiated
	state          OrchestratorState
	stateEntryTime time.Time // when the orchestrator entered the current state

	staleTimeout time.Duration
	// lastActivityTime time.Time

	pendingEvents chan ptmgrtypes.PrivateTransactionEvent

	contractAddress     string // the contract address managed by the current orchestrator
	nodeID              string
	domainAPI           components.DomainSmartContract
	sequencer           ptmgrtypes.Sequencer
	components          components.PreInitComponentsAndManagers
	endorsementGatherer ptmgrtypes.EndorsementGatherer
	publisher           ptmgrtypes.Publisher

	store privatetxnstore.Store

	baseLedgerTransactionManager enginespi.BaseLedgerTxEngine
}

var orchestratorConfigDefault = OrchestratorConfig{
	MaxConcurrentProcess:    confutil.P(500),
	StageRetry:              confutil.P("5s"),
	EvaluationInterval:      confutil.P("5m"),
	PersistenceRetryTimeout: confutil.P("5s"),
	StaleTimeout:            confutil.P("10m"),
	MaxPendingEvents:        confutil.P(500),
}

func NewOrchestrator(ctx context.Context, nodeID string, contractAddress string, oc *OrchestratorConfig, allComponents components.PreInitComponentsAndManagers, domainAPI components.DomainSmartContract, sequencer ptmgrtypes.Sequencer, endorsementGatherer ptmgrtypes.EndorsementGatherer, publisher ptmgrtypes.Publisher) *Orchestrator {

	newOrchestrator := &Orchestrator{
		ctx:                  log.WithLogField(ctx, "role", fmt.Sprintf("orchestrator-%s", contractAddress)),
		initiated:            time.Now(),
		contractAddress:      contractAddress,
		evalInterval:         confutil.DurationMin(oc.EvaluationInterval, 1*time.Millisecond, *orchestratorConfigDefault.EvaluationInterval),
		maxConcurrentProcess: confutil.Int(oc.MaxConcurrentProcess, *orchestratorConfigDefault.MaxConcurrentProcess),
		state:                OrchestratorStateNew,
		stateEntryTime:       time.Now(),

		incompleteTxSProcessMap: make(map[string]ptmgrtypes.TxProcessor),
		stageRetryTimeout:       confutil.DurationMin(oc.StageRetry, 1*time.Millisecond, *orchestratorConfigDefault.StageRetry),
		persistenceRetryTimeout: confutil.DurationMin(oc.PersistenceRetryTimeout, 1*time.Millisecond, *orchestratorConfigDefault.PersistenceRetryTimeout),

		staleTimeout:                 confutil.DurationMin(oc.StaleTimeout, 1*time.Millisecond, *orchestratorConfigDefault.StageRetry),
		processedTxIDs:               make(map[string]bool),
		orchestrationEvalRequestChan: make(chan bool, 1),
		stopProcess:                  make(chan bool, 1),
		pendingEvents:                make(chan ptmgrtypes.PrivateTransactionEvent, *orchestratorConfigDefault.MaxPendingEvents),
		nodeID:                       nodeID,
		domainAPI:                    domainAPI,
		sequencer:                    sequencer,
		components:                   allComponents,
		endorsementGatherer:          endorsementGatherer,
		publisher:                    publisher,
	}

	newOrchestrator.sequencer = sequencer
	sequencer.SetDispatcher(newOrchestrator)
	log.L(ctx).Debugf("NewOrchestrator for contract address %s created: %+v", newOrchestrator.contractAddress, newOrchestrator)

	return newOrchestrator
}

func (oc *Orchestrator) getTransactionProcessor(txID string) ptmgrtypes.TxProcessor {
	oc.incompleteTxProcessMapMutex.Lock()
	defer oc.incompleteTxProcessMapMutex.Unlock()
	//TODO if the transaction is not in memory, we need to load it from the database
	return oc.incompleteTxSProcessMap[txID]
}

func (oc *Orchestrator) handleEvent(ctx context.Context, event ptmgrtypes.PrivateTransactionEvent) {
	//For any event that is specific to a single transaction,
	// find (or create) the transaction processor for that transaction
	// and pass the event to it
	transactionID := event.GetTransactionID()
	transactionProccessor := oc.getTransactionProcessor(transactionID)
	switch event := event.(type) {
	case *ptmgrtypes.TransactionSubmittedEvent:
		transactionProccessor.HandleTransactionSubmittedEvent(ctx, event)
	case *ptmgrtypes.TransactionAssembledEvent:
		transactionProccessor.HandleTransactionAssembledEvent(ctx, event)
	case *ptmgrtypes.TransactionSignedEvent:
		transactionProccessor.HandleTransactionSignedEvent(ctx, event)
	case *ptmgrtypes.TransactionEndorsedEvent:
		transactionProccessor.HandleTransactionEndorsedEvent(ctx, event)
	case *ptmgrtypes.TransactionDispatchedEvent:
		transactionProccessor.HandleTransactionDispatchedEvent(ctx, event)
	case *ptmgrtypes.TransactionConfirmedEvent:
		transactionProccessor.HandleTransactionConfirmedEvent(ctx, event)
	case *ptmgrtypes.TransactionRevertedEvent:
		transactionProccessor.HandleTransactionRevertedEvent(ctx, event)
	case *ptmgrtypes.TransactionDelegatedEvent:
		transactionProccessor.HandleTransactionDelegatedEvent(ctx, event)
	default:
		log.L(ctx).Warnf("Unknown event type: %T", event)
	}
}

func (oc *Orchestrator) evaluationLoop() {
	// Select from the event channel and process each event on a single thread
	// individual event handlers are responsible for kicking off another go routine if they have
	// long running tasks that are not dependant on the order of events
	// if the channel ever fills up, then we need to be aware that we have potentially missed some events
	// and we need to poll the database for any events that we missed

	ctx := log.WithLogField(oc.ctx, "role", fmt.Sprintf("pctm-loop-%s", oc.contractAddress))
	log.L(ctx).Infof("Orchestrator for contract address %s started evaluation loop based on interval %s", oc.contractAddress, oc.evalInterval)

	defer close(oc.orchestratorLoopDone)

	ticker := time.NewTicker(oc.evalInterval)
	for {
		// an InFlight
		select {
		case pendingEvent := <-oc.pendingEvents:
			oc.handleEvent(ctx, pendingEvent)
		case <-oc.orchestrationEvalRequestChan:
		case <-ticker.C:
		case <-ctx.Done():
			log.L(ctx).Infof("Orchestrator loop exit due to canceled context, it processed %d transaction during its lifetime.", oc.totalCompleted)
			return
		case <-oc.stopProcess:
			log.L(ctx).Infof("Orchestrator loop process stopped, it processed %d transaction during its lifetime.", oc.totalCompleted)
			oc.state = OrchestratorStateStopped
			oc.stateEntryTime = time.Now()
			// TODO: trigger parent loop for removal
			return
		}
		added, total := oc.evaluateTransactions(ctx)
		log.L(ctx).Debugf("Orchestrator loop added %d txs, there are %d txs in total", added, total)
	}
}

func (oc *Orchestrator) evaluateTransactions(ctx context.Context) (added int, newTotal int) {
	evalStart := time.Now()
	oc.incompleteTxProcessMapMutex.Lock()
	defer oc.incompleteTxProcessMapMutex.Unlock()
	// hasActivity := false

	oldIncompleteMap := oc.incompleteTxSProcessMap
	oc.incompleteTxSProcessMap = make(map[string]ptmgrtypes.TxProcessor, len(oldIncompleteMap))

	for txID, txp := range oldIncompleteMap {
		oc.processedTxIDs[txID] = true
		sc := txp.GetStatus(ctx)
		if sc == ptmgrtypes.TxProcessorRemove {
			// no longer in an incomplete stage
			oc.totalCompleted = oc.totalCompleted + 1
			// hasActivity = true
			log.L(ctx).Debugf("Orchestrator evaluate and process, marking %s as complete.", txID)
			break
		} else if sc == ptmgrtypes.TxProcessorSuspend {
			log.L(ctx).Debugf("Orchestrator evaluate and process, removed suspended tx %s", txID)
			break
		}
		oc.incompleteTxSProcessMap[txID] = txp
	}

	log.L(ctx).Debugf("Orchestrator evaluate and process")

	oldTotal := len(oc.incompleteTxSProcessMap)
	newTotal = oldTotal

	// in case there are event we missed
	// check and evaluate new transactions from the persistence if we can handle more
	// If we are not at maximum, then query if there are more candidates now

	// spaces := oc.maxConcurrentProcess - oldTotal
	// if spaces > 0 {
	// 	completedTxIDsStillBeingPersisted := make(map[string]bool)
	// 	// TODO: evaluate and put kick off stage processing for transactions
	// 	oc.processedTxIDs = completedTxIDsStillBeingPersisted
	// 	newTotal = len(oc.incompleteTxSProcessMap)
	// 	added = newTotal - oldTotal
	// 	if added > 0 {
	// 		log.L(ctx).Infof("Evaluation loop added %d new transactions", added)
	// 	}
	// 	// TODO: emit metrics
	// }
	log.L(ctx).Debugf("Orchestrator evaluate from DB took %s", time.Since(evalStart))
	// now check and process each transaction

	// if newTotal > 0 {
	// 	blockedByPreReq := oc.ProcessIncompleteTransactions(ctx, oc.incompleteTxSProcessMap)
	// 	if hasActivity {
	// 		oc.lastActivityTime = time.Now()
	// 	}
	// 	if time.Since(oc.lastActivityTime) > oc.staleTimeout && oc.state != OrchestratorStateStale {
	// 		oc.state = OrchestratorStateStale
	// 		oc.stateEntryTime = time.Now()
	// 	} else if blockedByPreReq && oc.state != OrchestratorStateWaiting {
	// 		oc.state = OrchestratorStateWaiting
	// 		oc.stateEntryTime = time.Now()
	// 	} else if oc.state != OrchestratorStateRunning {
	// 		oc.state = OrchestratorStateRunning
	// 		oc.stateEntryTime = time.Now()
	// 	}
	// } else if oc.state != OrchestratorStateIdle {
	// 	oc.state = OrchestratorStateIdle
	// 	oc.stateEntryTime = time.Now()
	// }
	log.L(ctx).Debugf("Orchestrator process loop took %s", time.Since(evalStart))
	return added, newTotal
}

func (oc *Orchestrator) ProcessNewTransaction(ctx context.Context, tx *components.PrivateTransaction) (queued bool) {
	oc.incompleteTxProcessMapMutex.Lock()
	defer oc.incompleteTxProcessMapMutex.Unlock()
	if oc.incompleteTxSProcessMap[tx.ID.String()] == nil {
		if len(oc.incompleteTxSProcessMap) >= oc.maxConcurrentProcess {
			// TODO: decide how this map is managed, it shouldn't track the entire lifecycle
			// tx processing pool is full, queue the item
			return true
		} else {
			oc.incompleteTxSProcessMap[tx.ID.String()] = NewPaladinTransactionProcessor(ctx, tx, oc.nodeID, oc.components, oc.domainAPI, oc.sequencer, oc.publisher, oc.endorsementGatherer)
		}
		oc.incompleteTxSProcessMap[tx.ID.String()].Init(ctx)
		oc.pendingEvents <- &ptmgrtypes.TransactionSubmittedEvent{
			PrivateTransactionEventBase: ptmgrtypes.PrivateTransactionEventBase{TransactionID: tx.ID.String()},
		}
	}
	return false
}

func (oc *Orchestrator) HandleEvent(ctx context.Context, event ptmgrtypes.PrivateTransactionEvent) {
	//TODO Better
	oc.incompleteTxProcessMapMutex.Lock()
	defer oc.incompleteTxProcessMapMutex.Unlock()
	txProc := oc.incompleteTxSProcessMap[event.GetTransactionID()]
	if txProc == nil {
		// TODO: is bypassing max concurrent process correct?
		// or throw the event away and waste another cycle to redo the actions
		// (doesn't feel right, maybe for some events only persistence is needed)

		// TODO we have an event for a transaction that we have swapped out of memory.  Need to reload the transaction from the database before we can proces this event
		// and we need to do this in a way that doesn't exceed the maxConcurrentProcess and doesn't allow events from a runaway remote node to cause a noisy neighbor problem for events
		// from the local node
		panic("Transaction not found")

	}
	oc.pendingEvents <- event
}

func (oc *Orchestrator) Start(c context.Context) (done <-chan struct{}, err error) {
	oc.orchestratorLoopDone = make(chan struct{})
	go oc.evaluationLoop()
	oc.TriggerOrchestratorEvaluation()
	return oc.orchestratorLoopDone, nil
}

// Stop the InFlight transaction process.
func (oc *Orchestrator) Stop() {
	// try to send an item in `stopProcess` channel, which has a buffer of 1
	// if it already has an item in the channel, this function does nothing
	select {
	case oc.stopProcess <- true:
	default:
	}

}

func (oc *Orchestrator) TriggerOrchestratorEvaluation() {
	// try to send an item in `processNow` channel, which has a buffer of 1
	// if it already has an item in the channel, this function does nothing
	select {
	case oc.orchestrationEvalRequestChan <- true:
	default:
	}
}

func (oc *Orchestrator) GetTxStatus(ctx context.Context, txID string) (status ptmgrtypes.TxStatus, err error) {
	//TODO This is primarily here to help with testing for now
	// this needs to be revisited ASAP as part of a holisitic review of the persistence model
	oc.incompleteTxProcessMapMutex.Lock()
	defer oc.incompleteTxProcessMapMutex.Unlock()
	if txProc, ok := oc.incompleteTxSProcessMap[txID]; ok {
		return txProc.GetTxStatus(ctx)
	}
	//TODO should be possible to query the status of a transaction that is not inflight
	return ptmgrtypes.TxStatus{}, i18n.NewError(ctx, msgs.MsgEngineInternalError, "Transaction not found")
}

// synchronously prepare and dispatch all given transactions to their associated signing address
func (oc *Orchestrator) DispatchTransactions(ctx context.Context, dispatchableTransactions ptmgrtypes.DispatchableTransactions) error {

	//prepare all transactions then dispatch them

	// array of batches with space for one batch per signing address
	dispatchBatch := &privatetxnstore.DispatchBatch{
		DispatchSequences: make([]*privatetxnstore.DispatchSequence, 0, len(dispatchableTransactions)),
	}

	for signingAddress, transactionIDs := range dispatchableTransactions {
		preparedTransactions := make([]*components.PrivateTransaction, len(transactionIDs))
		sequence := &privatetxnstore.DispatchSequence{
			PrivateTransactionDispatches: make([]*privatetxnstore.DispatchPersisted, len(transactionIDs)),
		}
		for i, transactionID := range transactionIDs {
			sequence.PrivateTransactionDispatches[i] = &privatetxnstore.DispatchPersisted{
				PrivateTransactionID: transactionID,
			}

			txProcessor := oc.getTransactionProcessor(transactionID)
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
			preparedTransactions[i] = preparedTransaction
			preparedTransactionPayloads := make([]*components.EthTransaction, len(preparedTransactions))

			convertToInterfaceSlice := func(slice []*components.EthTransaction) []interface{} {
				converted := make([]interface{}, len(slice))
				for i, v := range slice {
					converted[i] = v
				}
				return converted
			}

			for j, preparedTransaction := range preparedTransactions {
				preparedTransactionPayloads[j] = preparedTransaction.PreparedTransaction
			}
			preparedSubmissions, rejected, err := oc.baseLedgerTransactionManager.PrepareSubmissionBatch(ctx,
				&enginespi.RequestOptions{
					SignerID: signingAddress,
				},
				convertToInterfaceSlice(preparedTransactionPayloads),
			)
			if rejected {
				log.L(ctx).Errorf("Submission rejected")
				return i18n.NewError(ctx, msgs.MsgEngineInternalError, "Submission rejected")
			}
			if err != nil {
				log.L(ctx).Errorf("Error preparing submission batch: %s", err)
				return err
			}

			sequence.PublicTransactionsSubmit = func() (publicTxIDs []string, err error) {
				//TODO submit the public transactions
				manageTransactions, err := oc.baseLedgerTransactionManager.SubmitBatch(ctx, preparedSubmissions)
				if err != nil {
					log.L(ctx).Errorf("Error submitting batch: %s", err)
					return nil, err
				}
				publicTxIDs = make([]string, len(manageTransactions))
				for i, manageTransaction := range manageTransactions {
					publicTxIDs[i] = manageTransaction.ID
				}

				return nil, nil
			}

		}
		dispatchBatch.DispatchSequences = append(dispatchBatch.DispatchSequences, sequence)
	}

	oc.store.PersistDispatchBatch(ctx, dispatchBatch)

	for signingAddress, sequence := range dispatchableTransactions {
		for _, privateTransactionID := range sequence {
			err := oc.publisher.PublishTransactionDispatchedEvent(ctx, privateTransactionID, uint64(0) /*TODO*/, signingAddress)

			if err != nil {
				//TODO think about how best to handle this error
				log.L(ctx).Errorf("Error publishing stage event: %s", err)
			}
		}
	}

	return nil

}
