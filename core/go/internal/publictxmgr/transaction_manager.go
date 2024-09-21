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

package publictxmgr

import (
	"context"
	"math/big"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-signer/pkg/ethsigner"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/kaleido-io/paladin/core/internal/components"
	baseTypes "github.com/kaleido-io/paladin/core/internal/engine/enginespi"
	"github.com/kaleido-io/paladin/core/pkg/blockindexer"
	"github.com/kaleido-io/paladin/core/pkg/ethclient"
	"github.com/kaleido-io/paladin/core/pkg/persistence"
	"github.com/kaleido-io/paladin/toolkit/pkg/confutil"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/ptxapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/retry"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"

	"github.com/kaleido-io/paladin/core/internal/msgs"

	"github.com/kaleido-io/paladin/toolkit/pkg/algorithms"
	"gorm.io/gorm"
)

// configurations
// metrics

// UpdateType informs policy loop whether the transaction needs an update to be persisted after a transaction processor finished processing a transaction
type UpdateType int

const (
	UpdateNo     UpdateType = iota // Instructs that no update is necessary
	UpdateYes                      // Instructs that the transaction should be updated in persistence
	UpdateDelete                   // Instructs that the transaction should be removed completely from persistence - generally only returned when TX status is TxStatusDeleteRequested
)

// Public Tx Engine:
// - It offers two ways of calculating gas price: use a fixed number, use the built-in API of a ethereum connector
// - It resubmits the transaction based on a configured interval until it succeed or fail
// - It also recalculate gas price during resubmissions
// - It logs errors transactions breach certain configured thresholds of staleness
// - It offers caches of gas price for transactions targeting same method of a smart contract
// - It provide a outbound request concurrency control

type pubTxManager struct {
	ctx       context.Context
	ctxCancel context.CancelFunc

	conf      *Config
	thMetrics *publicTxEngineMetrics
	p         persistence.Persistence
	bIndexer  blockindexer.BlockIndexer
	ethClient ethclient.EthClient
	keymgr    ethclient.KeyManager
	// gas price
	gasPriceClient GasPriceClient

	// nonce manager
	nonceManager baseTypes.NonceCache

	// a map of signing addresses and transaction engines
	InFlightOrchestrators       map[string]*orchestrator
	SigningAddressesPausedUntil map[string]time.Time
	InFlightOrchestratorMux     sync.Mutex
	InFlightOrchestratorStale   chan bool

	// a map of signing addresses and the highest nonce of their completed transactions
	completedTxNoncePerAddress      map[string]big.Int
	completedTxNoncePerAddressMutex sync.Mutex

	// a map of signing addresses and the highest nonce of their confirmed transactions seen from the block indexer
	confirmedTxNoncePerAddress        map[string]*big.Int
	confirmedTxNoncePerAddressRWMutex sync.RWMutex

	// inbound concurrency control TBD

	// engine config
	maxInFlightOrchestrators int
	maxOrchestratorStale     time.Duration
	maxOrchestratorIdle      time.Duration
	maxOverloadProcessTime   time.Duration
	retry                    *retry.Retry
	enginePollingInterval    time.Duration
	engineLoopDone           chan struct{}

	// balance manager
	balanceManager baseTypes.BalanceManager

	// orchestrator config
	gasPriceIncreaseMax     *big.Int
	gasPriceIncreasePercent int
}

func NewPublicTransactionManager(ctx context.Context, conf *Config) components.PublicTxManager {
	log.L(ctx).Debugf("Creating new enterprise transaction handler")

	gasPriceClient := NewGasPriceClient(ctx, conf)
	gasPriceIncreaseMax := confutil.BigIntOrNil(conf.GasPrice.IncreaseMax)

	log.L(ctx).Debugf("Enterprise transaction handler created")

	ptmCtx, ptmCtxCancel := context.WithCancel(log.WithLogField(ctx, "role", "public_tx_mgr"))

	return &pubTxManager{
		ctx:                         ptmCtx,
		ctxCancel:                   ptmCtxCancel,
		gasPriceClient:              gasPriceClient,
		InFlightOrchestratorStale:   make(chan bool, 1),
		SigningAddressesPausedUntil: make(map[string]time.Time),
		maxInFlightOrchestrators:    confutil.IntMin(conf.Orchestrator.MaxInFlight, 1, *DefaultConfig.Orchestrator.MaxInFlight),
		maxOverloadProcessTime:      confutil.DurationMin(conf.TransactionEngine.MaxOverloadProcessTime, 0, *DefaultConfig.TransactionEngine.MaxOverloadProcessTime),
		maxOrchestratorStale:        confutil.DurationMin(conf.TransactionEngine.MaxStaleTime, 0, *DefaultConfig.TransactionEngine.MaxStaleTime),
		maxOrchestratorIdle:         confutil.DurationMin(conf.TransactionEngine.MaxIdleTime, 0, *DefaultConfig.TransactionEngine.MaxIdleTime),
		enginePollingInterval:       confutil.DurationMin(conf.TransactionEngine.Interval, 50*time.Millisecond, *conf.TransactionEngine.Interval),
		retry:                       retry.NewRetryIndefinite(&conf.TransactionEngine.Retry),
		completedTxNoncePerAddress:  make(map[string]big.Int),
		confirmedTxNoncePerAddress:  make(map[string]*big.Int),
		gasPriceIncreaseMax:         gasPriceIncreaseMax,
		gasPriceIncreasePercent:     confutil.Int(conf.GasPrice.IncreasePercentage, *DefaultConfig.GasPrice.IncreasePercentage),
	}
}

// Post-init allows the manager to cross-bind to other components, or the Engine
func (ble *pubTxManager) PostInit(components.AllComponents) error {
	return nil
}

func (ble *pubTxManager) PreInit(pic components.PreInitComponents) (result *components.ManagerInitResult, err error) {
	ctx := ble.ctx
	log.L(ctx).Debugf("Initializing enterprise transaction handler")
	ble.ethClient = pic.EthClientFactory().SharedWS()
	ble.keymgr = pic.KeyManager()
	ble.gasPriceClient.Init(ctx, ble.ethClient)
	ble.bIndexer = pic.BlockIndexer()
	ble.nonceManager = newNonceCache(1*time.Hour, func(ctx context.Context, signer string) (uint64, error) {
		log.L(ctx).Tracef("NonceFromChain getting next nonce for signing address ID %s", signer)
		nextNonce, err := ble.ethClient.GetTransactionCount(ctx, signer)
		if err != nil {
			log.L(ctx).Errorf("NonceFromChain getting next nonce for signer %s failed: %+v", signer, err)
			return 0, err
		}
		log.L(ctx).Tracef("NonceFromChain getting next nonce for signer %s succeeded: %s, converting to uint: %d", signer, nextNonce.String(), nextNonce.Uint64())
		return nextNonce.Uint64(), nil
	})

	balanceManager, err := NewBalanceManagerWithInMemoryTracking(ctx, ble.conf, ble.ethClient, ble)
	if err != nil {
		log.L(ctx).Errorf("Failed to create balance manager for enterprise transaction handler due to %+v", err)
		panic(err)
	}
	log.L(ctx).Debugf("Initialized enterprise transaction handler")
	ble.balanceManager = balanceManager
	return &components.ManagerInitResult{}, nil
}

func (ble *pubTxManager) Start() error {
	ctx := ble.ctx
	log.L(ctx).Debugf("Starting enterprise transaction handler")
	if ble.ctx == nil { // only start once
		ble.ctx = ctx // set the context for policy loop
		ble.engineLoopDone = make(chan struct{})
		log.L(ctx).Debugf("Kicking off  enterprise handler engine loop")
		go ble.engineLoop()
	}
	ble.MarkInFlightOrchestratorsStale()
	log.L(ctx).Infof("Started enterprise transaction handler")
	return nil
}

func (ble *pubTxManager) Stop() {
	ble.ctxCancel()
	<-ble.engineLoopDone
}

type preparedTransaction struct {
	ethTx *ethsigner.Transaction
	id    string
	nsi   baseTypes.NonceAssignmentIntent
}

func (pt *preparedTransaction) ID() string {
	return pt.id
}

func (pt *preparedTransaction) CleanUp(ctx context.Context) {
	pt.nsi.Rollback(ctx)
}
func (pt *preparedTransaction) Finalize(ctx context.Context) {
	pt.nsi.Complete(ctx)
}

func (ble *pubTxManager) PrepareSubmissionBatch(ctx context.Context, transactions []*ptxapi.PublicTxInput) (preparedSubmission []components.PublicTxPreparedSubmission, submissionRejected bool, err error) {
	preparedSubmissions := make([]components.PublicTxPreparedSubmission, len(transactions))
	var nsi baseTypes.NonceAssignmentIntent
	for i, tx := range transactions {
		preparedSubmission, submissionRejected, err := ble.PrepareSubmission(ctx, tx, nsi)
		if submissionRejected || err != nil {
			return nil, submissionRejected, err
		}
		preparedSubmissions[i] = preparedSubmission
		nsi = preparedSubmission.(*preparedTransaction).nsi
	}
	return preparedSubmissions, false, nil
}

func (ble *pubTxManager) buildEthTX(tx *ptxapi.PublicTxInput) *ethsigner.Transaction {
	return &ethsigner.Transaction{
		To:                   tx.To.Address0xHex(),
		GasLimit:             (*ethtypes.HexInteger)(tx.Gas),
		GasPrice:             (*ethtypes.HexInteger)(tx.GasPrice),
		MaxPriorityFeePerGas: (*ethtypes.HexInteger)(tx.MaxPriorityFeePerGas),
		MaxFeePerGas:         (*ethtypes.HexInteger)(tx.MaxFeePerGas),
		Value:                (*ethtypes.HexInteger)(tx.Value),
		Data:                 ethtypes.HexBytes0xPrefix(tx.Data),
	}
}

// PrepareSubmission prepares and validates the transaction input data so that a later call to
// Submit can be made in the middle of a wider database transaction with minimal risk of error
func (ble *pubTxManager) PrepareSubmission(ctx context.Context, tx *ptxapi.PublicTxInput, nonceAssignmentIntent baseTypes.NonceAssignmentIntent) (preparedSubmission components.PublicTxPreparedSubmission, submissionRejected bool, err error) {
	log.L(ctx).Tracef("PrepareSubmission transaction: %+v", tx)

	prepareStart := time.Now()
	var txType InFlightTxOperation

	if tx.Gas.NilOrZero() {
		estimatedGasLimitHexInt, err := ble.ethClient.GasEstimate(ctx, ble.buildEthTX(tx), nil /* TODO: Would be great to have the ABI errors available here */)
		if err != nil {
			log.L(ctx).Errorf("HandleNewTx <%s> error estimating gas for transfer request: %+v, request: (%+v)", txType, err, tx)
			ble.thMetrics.RecordOperationMetrics(ctx, string(txType), string(GenericStatusFail), time.Since(prepareStart).Seconds())
			return nil, ethclient.MapSubmissionRejected(err), err
		}
		tx.Gas = (*tktypes.HexUint256)(estimatedGasLimitHexInt)
		log.L(ctx).Tracef("HandleNewTx <%s> using the estimated gas limit %s for transfer request: %+v", txType, estimatedGasLimit.String(), txPayload)
	} else {
		log.L(ctx).Tracef("HandleNewTx <%s> using the provided gas limit %s for transfer request: %+v", txType, estimatedGasLimit.String(), txPayload)
	}

	nsi := nonceAssignmentIntent
	if nsi == nil {
		nsi, err = ble.nonceManager.IntentToAssignNonce(ctx, tx.From)
		if err != nil {
			log.L(ctx).Errorf("HandleNewTx <%s> error assigning nonce for transfer request: %+v, request: (%+v)", txType, err, txPayload)
			ble.thMetrics.RecordOperationMetrics(ctx, string(txType), string(GenericStatusFail), time.Since(prepareStart).Seconds())
			return nil, false, err
		}
	}
	ble.thMetrics.RecordOperationMetrics(ctx, string(txType), string(GenericStatusSuccess), time.Since(prepareStart).Seconds())
	log.L(ctx).Debugf("HandleNewTx <%s> creating a new managed transaction with ID %s", txType, reqOptions.ID)
	return &preparedTransaction{
		ethTx: ethTx,
		id:    reqOptions.ID.String(),
		nsi:   nsi,
	}, false, nil

}

// Submit writes the prepared submission to the database using the provided context
// This is expected to be a lightweight operation involving not much more than writing to the database, as the heavy lifting should have been done in PrepareSubmission
// The database transaction will be coordinated by the caller
func (ble *pubTxManager) Submit(ctx context.Context, dbtx *gorm.DB, preparedSubmission components.PreparedSubmission) (mtx *components.PublicTX, err error) {
	preparedTransaction := preparedSubmission.(*preparedTransaction)
	mtx, err = ble.createManagedTx(ctx, dbtx, preparedTransaction.ID(), preparedTransaction.ethTx, preparedTransaction.nsi)
	return mtx, err
}

func (ble *pubTxManager) SubmitBatch(ctx context.Context, dbtx *gorm.DB, preparedSubmissions []components.PreparedSubmission) ([]*components.PublicTX, error) {
	mtxBatch := make([]*components.PublicTX, len(preparedSubmissions))
	for i, preparedSubmission := range preparedSubmissions {
		mtx, err := ble.Submit(ctx, dbtx, preparedSubmission)
		if err != nil {
			return nil, err
		}
		mtxBatch[i] = mtx
	}
	return mtxBatch, nil
}

func (ble *pubTxManager) HandleNewTransaction(ctx context.Context, reqOptions *components.RequestOptions, txPayload interface{}) (mtx *components.PublicTX, submissionRejected bool, err error) {
	preparedSubmission, submissionRejected, err := ble.PrepareSubmission(ctx, reqOptions, txPayload, nil)
	if preparedSubmission != nil {
		defer preparedSubmission.CleanUp(ctx)
	}
	if submissionRejected || err != nil {
		return nil, submissionRejected, err
	}
	mtx, err = ble.Submit(ctx, nil, preparedSubmission)
	if err != nil {
		preparedSubmission.Finalize(ctx)
	}
	return
}

func (ble *pubTxManager) createManagedTx(ctx context.Context, dbtx *gorm.DB, txID string, ethTx *ethsigner.Transaction, nsi baseTypes.NonceAssignmentIntent) (*components.PublicTX, error) {
	log.L(ctx).Tracef("createManagedTx creating a new managed transaction with ID: %s, and payload %+v", txID, ethTx)
	nonce, err := nsi.AssignNextNonce(ctx)
	if err != nil {
		log.L(ctx).Errorf("createManagedTx failed to create managed traction with ID: %s, due to %+v", txID, err)
		return nil, err
	}
	ethTx.Nonce = ethtypes.NewHexIntegerU64(nonce)
	now := tktypes.TimestampNow()
	mtx := &components.PublicTX{
		ID:          uuid.MustParse(txID),
		Created:     now,
		Updated:     now,
		Transaction: ethTx,
		Status:      components.PubTxStatusPending,
	}

	log.L(ctx).Tracef("createManagedTx persisting managed transaction %+v", mtx)
	// Sequencing ID will be added as part of persistence logic - so we have a deterministic order of transactions
	// Note: We must ensure persistence happens this within the nonce lock, to ensure that the nonce sequence and the
	//       global transaction sequence line up.
	err = ble.txStore.InsertTransaction(ctx, dbtx, mtx)

	if err == nil {
		log.L(ctx).Tracef("createManagedTx persisted transaction with ID: %s, using nonce %s", mtx.ID, mtx.Nonce.String())
		err = ble.txStore.UpdateSubStatus(ctx, txID, components.PubTxSubStatusReceived, components.BaseTxActionAssignNonce, fftypes.JSONAnyPtr(`{"nonce":"`+mtx.Nonce.String()+`"}`), nil, confutil.P(tktypes.TimestampNow()))
	}
	if err != nil {
		log.L(ctx).Errorf("createManagedTx failed to create managed traction with ID: %s, due to %+v", mtx.ID, err)
		return nil, err
	}
	log.L(ctx).Debugf("createManagedTx a new managed transaction with ID %s is persisted", mtx.ID)
	ble.MarkInFlightOrchestratorsStale()

	return mtx, nil
}

// HandleConfirmedTransactions
// handover events to the inflight orchestrators for the related signing addresses and record the highest confirmed nonce
// new orchestrators will be created if there are space, orchestrators will use the recorded highest nonce to drive completion logic of transactions
func (ble *pubTxManager) HandleConfirmedTransactions(ctx context.Context, confirmedTransactions []*blockindexer.IndexedTransaction) error {
	// firstly, we group the confirmed transactions by from address
	// note: filter out transactions that are before the recorded nonce in confirmedTXNonce map requires multiple reads to a single address (as the loop keep switching between addresses)
	// so we delegate the logic to the orchestrator as it will have a list of records for a single address
	itMap := make(map[string]map[string]*blockindexer.IndexedTransaction)
	itMaxNonce := make(map[string]*big.Int)
	for _, it := range confirmedTransactions {
		itNonce := new(big.Int).SetUint64(it.Nonce)
		if itMap[it.From.String()] == nil {
			itMap[it.From.String()] = map[string]*blockindexer.IndexedTransaction{itNonce.String(): it}
		} else {
			itMap[it.From.String()][itNonce.String()] = it
		}
		if itMaxNonce[it.From.String()] == nil || itMaxNonce[it.From.String()].Cmp(itNonce) == -1 {
			itMaxNonce[it.From.String()] = itNonce
		}
	}
	if len(itMap) > 0 {
		// secondly, we obtain the lock for the orchestrator map:
		ble.InFlightOrchestratorMux.Lock()
		defer ble.InFlightOrchestratorMux.Unlock() // note, using lock might cause the event sequence to get lost when this function is invoked concurrently by several go routines, this code assumes the upstream logic does not do that

		//     for address that has or could have a running orchestrator, triggers event handlers of each orchestrator in parallel to handle the event
		//         (logic implemented in orchestrator handler)for the orchestrator handler, it obtains the stage process buffer lock and add the event into the stage process buffer and then exit

		localRWLock := sync.RWMutex{} // could consider switch InFlightOrchestrators to use sync.Map for this logic here as the go routines will only modify disjoint set of keys
		eventHandlingErrors := make(chan error, len(itMap))
		for from, its := range itMap {
			fromAddress := from
			indexedTxs := its
			go func() {
				localRWLock.RLock()
				inFlightOrchestrator := ble.InFlightOrchestrators[fromAddress]
				localRWLock.RUnlock()
				if inFlightOrchestrator == nil {
					localRWLock.Lock()
					itTotal := len(ble.InFlightOrchestrators)
					if itTotal < ble.maxInFlightOrchestrators {
						inFlightOrchestrator = NewOrchestrator(ble, fromAddress, ble.orchestratorConfig)
						ble.InFlightOrchestrators[fromAddress] = inFlightOrchestrator
						_, _ = inFlightOrchestrator.Start(ble.ctx)
						log.L(ctx).Infof("(Event handler) Engine added orchestrator for signing address %s", fromAddress)
						localRWLock.Unlock()
					} else {
						// no action can be taken
						log.L(ctx).Debugf("(Event handler) Cannot add orchestrator for signing address %s due to in-flight queue is full", fromAddress)
						localRWLock.Unlock()
						eventHandlingErrors <- nil
						return
					}
				}
				err := inFlightOrchestrator.HandleConfirmedTransactions(ctx, indexedTxs, itMaxNonce[fromAddress])
				// finally, we update the confirmed nonce for each address to the highest number that is observed ever. This then can be used by the orchestrator to retrospectively fetch missed confirmed transaction data.
				ble.updateConfirmedTxNonce(fromAddress, itMaxNonce[fromAddress])
				eventHandlingErrors <- err
			}()
		}

		resultCount := 0
		var accumulatedError error

		// wait for all add output to complete
		for {
			select {
			case err := <-eventHandlingErrors:
				if err != nil {
					accumulatedError = err
				}
				resultCount++
			case <-ctx.Done():
				return i18n.NewError(ctx, msgs.MsgContextCanceled)
			}
			if resultCount == len(itMap) {
				break
			}
		}
		return accumulatedError
	}
	return nil
}

func (ble *pubTxManager) HandleSuspendTransaction(ctx context.Context, txID string) (mtx *components.PublicTX, err error) {
	mtx, err = ble.txStore.GetTransactionByID(ctx, txID)
	if err != nil {
		return nil, err
	}
	res := ble.dispatchAction(ctx, mtx, ActionSuspend)
	if res.err != nil {
		return nil, res.err
	}
	return res.tx, nil
}

func (ble *pubTxManager) HandleResumeTransaction(ctx context.Context, txID string) (mtx *components.PublicTX, err error) {
	mtx, err = ble.txStore.GetTransactionByID(ctx, txID)
	if err != nil {
		return nil, err
	}
	res := ble.dispatchAction(ctx, mtx, ActionResume)
	if res.err != nil {
		return nil, res.err
	}
	return res.tx, nil
}

func (ble *pubTxManager) getConfirmedTxNonce(addr string) (nonce *big.Int) {
	ble.confirmedTxNoncePerAddressRWMutex.RLock()
	nonce = ble.confirmedTxNoncePerAddress[addr]
	defer ble.confirmedTxNoncePerAddressRWMutex.RUnlock()
	return
}

func (ble *pubTxManager) updateConfirmedTxNonce(addr string, nonce *big.Int) {
	ble.confirmedTxNoncePerAddressRWMutex.Lock()
	defer ble.confirmedTxNoncePerAddressRWMutex.Unlock()
	if ble.confirmedTxNoncePerAddress[addr] == nil || ble.confirmedTxNoncePerAddress[addr].Cmp(nonce) != 1 {
		ble.confirmedTxNoncePerAddress[addr] = nonce
	}
}
