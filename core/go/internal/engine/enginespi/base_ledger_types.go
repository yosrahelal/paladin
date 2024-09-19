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

package enginespi

import (
	"context"
	"math/big"
	"time"

	"github.com/google/uuid"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/pkg/blockindexer"
	"github.com/kaleido-io/paladin/core/pkg/ethclient"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"

	"github.com/hyperledger/firefly-common/pkg/fftypes"
)

type TransactionHeaders struct {
	From  string            `json:"from,omitempty"`
	To    string            `json:"to,omitempty"`
	Nonce *fftypes.FFBigInt `json:"nonce,omitempty"`
	Gas   *fftypes.FFBigInt `json:"gas,omitempty"`
	Value *fftypes.FFBigInt `json:"value,omitempty"`
}

type BalanceManager interface {
	TopUpAccount(ctx context.Context, addAccount *AddressAccount) (mtx *components.PublicTX, err error)
	IsAutoFuelingEnabled(ctx context.Context) bool
	GetAddressBalance(ctx context.Context, address string) (*AddressAccount, error)
	NotifyAddressBalanceChanged(ctx context.Context, address string)
}

type AutoFuelTransactionHandler interface {
}

// AddressAccount provides the following feature:
// - record a snapshot of the current balance of a signing address
// - record the total spent of a series of transaction emitted by this signing address
// - provide an interface to top up the signing address when spent is higher than the balance
type AddressAccount struct {
	Address               string
	Balance               *big.Int
	SpentTransactionCount int
	MinCost               *big.Int
	MaxCost               *big.Int
	Spent                 *big.Int
}

func (ab *AddressAccount) Spend(ctx context.Context, cost *big.Int) (availableToSpend *big.Int) {

	if cost.Sign() == 1 {
		ab.Spent = ab.Spent.Add(ab.Spent, cost)
		if ab.MinCost.Sign() == 0 || ab.MinCost.Cmp(cost) > 0 {
			ab.MinCost = cost
		}

		if ab.MaxCost.Sign() == 0 || ab.MaxCost.Cmp(cost) < 0 {
			ab.MaxCost = cost
		}
		// only increase the transaction count if there is a positive cost number
		ab.SpentTransactionCount = ab.SpentTransactionCount + 1
	} else if cost.Sign() == -1 {
		// cost cannot be a negative value...
		log.L(ctx).Errorf("Received a negative number for transaction cost: %s, ignore the cost and keep address balance unchanged.", cost.String())
	}
	availableToSpend = ab.GetAvailableToSpend(ctx)
	return availableToSpend
}

func (ab *AddressAccount) GetAvailableToSpend(ctx context.Context) *big.Int {
	balanceCopy := new(big.Int).Set(ab.Balance)
	return balanceCopy.Sub(balanceCopy, ab.Spent)
}

type Confirmation struct {
	BlockNumber fftypes.FFuint64 `json:"blockNumber"`
	BlockHash   string           `json:"blockHash"`
	ParentHash  string           `json:"parentHash"`
}

type ConfirmationsNotification struct {
	// Confirmed marks we've reached the confirmation threshold
	Confirmed bool
	// NewFork is true when NewConfirmations is a complete list of confirmations.
	// Otherwise, Confirmations is an additive delta on top of a previous list of confirmations.
	NewFork bool
	// Confirmations is the list of confirmations being notified - assured to be non-nil, but might be empty.
	Confirmations []*Confirmation
}

type GasPriceObject struct {
	MaxPriorityFeePerGas *big.Int `json:"maxPriorityFeePerGas,omitempty"`
	MaxFeePerGas         *big.Int `json:"maxFeePerGas,omitempty"`
	GasPrice             *big.Int `json:"gasPrice,omitempty"`
}

// in flight tx stages are calculated based on a snapshot of a persisted managed transaction
//
//	an in flight stage can contain 1 or more sub-status updates
type InFlightTxStage string

const (
	// managed transaction criteria for entering each stage:
	//   entry criteria:
	//     transaction in a state that requires status update
	//   emitted async actions (in parallel):
	//     status update
	//   completion criteria
	//     status update completed
	InFlightTxStageStatusUpdate InFlightTxStage = "statusUpdate"

	//   entry criteria (OR):
	//     no gas price substatus since the most recent expired "submit" / "receipt" substatus or the beginning of substatus array
	//     no gas limit since the most recent expired "submit" / "receipt" substatus or the beginning of substatus array
	//   emitted async actions (in parallel):
	//     - retrieve gas price
	//     - get gas limit (TBD, current the gas estimation only happens before transaction process, need to fix this)
	//   completion criteria -> sign
	//     valid gas price and gas limit substatus since the most recent expired "submit" / "receipt" substatus or the beginning of substatus array
	InFlightTxStageRetrieveGasPrice InFlightTxStage = "retrieveGasPrice"
	//   entry criteria (AND):
	//     valid gas price and gas limit substatus since the most recent expired "submit" / "receipt" substatus or the beginning of substatus array
	//     no completed "sign" substatus with signed message value since above criteria
	//   emitted async actions:
	//     - signing request
	//   completion criteria -> submit
	//     the last sub-status is a completed (success) "sign" substatus
	InFlightTxStageSigning InFlightTxStage = "sign"
	//   entry criteria (OR):
	//     the last sub-status is a completed "sign" substatus
	//     the last sub-status is an incomplete "submit" substatus
	//   emitted async actions:
	//     - transaction submission
	//          wait condition when balance check turned on:
	//            - in-sufficient balance
	//            - cost of transaction with previous nonce unknown
	//   completion criteria -> receipt / prepare
	//     the last sub-status is a completed (success/expired) "submit" substatus
	InFlightTxStageSubmitting InFlightTxStage = "submit"
	//   entry criteria:
	//     there is a completed "receipt" substatus (!!!second high priority)
	//   completion criteria -> complete
	//      the last sub-status is a completed "confirmed" substatus
	InFlightTxStageConfirming InFlightTxStage = "confirm"
	//   entry criteria(OR):
	//     the last sub-status is a completed "confirmed" substatus
	//   end of lifecycle, rely on transaction engine to remove the item from the queue
	InFlightTxStageComplete InFlightTxStage = "complete"

	//   entry criteria:
	//     not in other state
	//   completion criteria
	//      evaluated into other state
	InFlightTxStageQueued InFlightTxStage = "queued"
)

var AllInFlightStages = []string{
	string(InFlightTxStageRetrieveGasPrice),
	string(InFlightTxStageSigning),
	string(InFlightTxStageSubmitting),
	string(InFlightTxStageConfirming),
	string(InFlightTxStageComplete),
	string(InFlightTxStageQueued),
}

type SubmissionOutcome string

const (
	// continue cases
	SubmissionOutcomeSubmittedNew SubmissionOutcome = "submittedNew"
	SubmissionOutcomeNonceTooLow  SubmissionOutcome = "nonceTooLow"
	SubmissionOutcomeAlreadyKnown SubmissionOutcome = "alreadyKnown"

	// error cases
	SubmissionOutcomeFailedRequiresRetry SubmissionOutcome = "errRequiresRetry"
)

type InMemoryTxStateReadOnly interface {
	GetTxID() uuid.UUID
	GetCreatedTime() *tktypes.Timestamp
	// get the transaction receipt from the in-memory state (note: the returned value should not be modified)
	GetConfirmedTransaction() *blockindexer.IndexedTransaction
	GetTransactionHash() *tktypes.Bytes32
	GetNonce() *big.Int
	GetFrom() string
	GetStatus() components.PubTxStatus
	GetGasPriceObject() *GasPriceObject
	GetFirstSubmit() *tktypes.Timestamp
	GetLastSubmitTime() *tktypes.Timestamp
	GetSubmittedHashes() []string

	GetTx() *components.PublicTX //TODO: remove the need of this function

	GetGasLimit() *big.Int
	IsComplete() bool
	IsSuspended() bool
}
type InMemoryTxStateManager interface {
	InMemoryTxStateReadOnly
	InMemoryTxStateSetters
}

type InMemoryTxStateSetters interface {
	SetConfirmedTransaction(ctx context.Context, iTX *blockindexer.IndexedTransaction)
	ApplyTxUpdates(ctx context.Context, txUpdates *components.BaseTXUpdates)
}

type StageOutput struct {
	Stage InFlightTxStage

	PersistenceOutput *PersistenceOutput

	SubmitOutput *SubmitOutputs

	SignOutput *SignOutputs

	GasPriceOutput *GasPriceOutput

	ConfirmationOutput *ConfirmationOutputs
}

type SubmitOutputs struct {
	TxHash            *tktypes.Bytes32
	SubmissionTime    *tktypes.Timestamp
	SubmissionOutcome SubmissionOutcome
	ErrorReason       string
	Err               error
}
type SignOutputs struct {
	SignedMessage []byte
	TxHash        string
	Err           error
}

type GasPriceOutput struct {
	GasPriceObject *GasPriceObject
	Err            error
}

type ConfirmationOutputs struct {
	ConfirmedTransaction *blockindexer.IndexedTransaction
	Err                  error
}

type PersistenceOutput struct {
	PersistenceError error
	Time             time.Time
}

type InFlightStageActionTriggers interface {
	TriggerRetrieveGasPrice(ctx context.Context) error
	TriggerSignTx(ctx context.Context) error
	TriggerSubmitTx(ctx context.Context, signedMessage []byte) error
	TriggerStatusUpdate(ctx context.Context) error
}

// RunningStageContext is the context for an individual run of the transaction process
type RunningStageContext struct {
	InMemoryTx InMemoryTxStateReadOnly
	context.Context
	Stage          InFlightTxStage
	SubStatus      components.PubTxSubStatus
	StageStartTime time.Time
	StageErrored   bool

	// for some stages, it requires inputs from multiple async request
	// this object is used to accumulate all the request result
	// the stage processing logic can decide whether there is a need to use this
	StageOutput *StageOutput

	StageOutputsToBePersisted *RunningStageContextPersistenceOutput
}

func (ctx *RunningStageContext) SetSubStatus(subStatus components.PubTxSubStatus) {
	ctx.SubStatus = subStatus
}

func (ctx *RunningStageContext) SetNewPersistenceUpdateOutput() {
	if ctx.StageOutputsToBePersisted == nil {
		ctx.StageOutputsToBePersisted = &RunningStageContextPersistenceOutput{
			UpdateType: PersistenceUpdateUpdate,
			InMemoryTx: ctx.InMemoryTx,
			SubStatus:  ctx.SubStatus,
			Ctx:        ctx,
		}
	}
}

type RunningStageContextPersistenceOutput struct {
	UpdateType              PersistenceUpdateType
	InMemoryTx              InMemoryTxStateReadOnly
	SubStatus               components.PubTxSubStatus
	Ctx                     context.Context
	TxUpdates               *components.BaseTXUpdates
	HistoryUpdates          []func(p components.PublicTransactionStore) error
	ConfirmedTransaction    *blockindexer.IndexedTransaction
	MissedConfirmationEvent bool
}

func (sOut *RunningStageContextPersistenceOutput) AddSubStatusAction(action components.BaseTxAction, info *fftypes.JSONAny, err *fftypes.JSONAny) {
	actionOccurred := fftypes.Now()
	sOut.HistoryUpdates = append(sOut.HistoryUpdates, func(p components.PublicTransactionStore) error {
		return p.AddSubStatusAction(sOut.Ctx, sOut.InMemoryTx.GetTxID().String(), sOut.SubStatus, action, info, err, actionOccurred)
	})
}

// UpdateType informs FFTM whether the transaction needs an update to be persisted after this execution of the policy engine
type PersistenceUpdateType int

const (
	PersistenceUpdateUpdate PersistenceUpdateType = iota // Instructs that the transaction should be updated in persistence
	// persistenceUpdateDelete                              // Instructs that the transaction should be removed completely from persistence - not sure it's safe to do so
)

type OrchestratorContext struct {
	// input from transaction engine
	AvailableToSpend         *big.Int
	PreviousNonceCostUnknown bool
	CurrentConfirmedNonce    *big.Int
}

// output of some stages doesn't get written into the database
// so it needs to be carried over to next stages
type TransientPreviousStageOutputs struct {
	SignedMessage []byte // NB: if the value is nil when triggering submitTx , node signer will be used to sign the transaction instead, don't use this to judge whether a transaction can be submitted or not.
}

type InFlightTransactionStateManager interface {
	// tx state management
	InMemoryTxStateReadOnly
	CanSubmit(ctx context.Context, cost *big.Int) bool
	CanBeRemoved(ctx context.Context) bool

	// stage management
	StartNewStageContext(ctx context.Context, stage InFlightTxStage, substatus components.PubTxSubStatus)
	GetStage(ctx context.Context) InFlightTxStage
	SetOrchestratorContext(ctx context.Context, tec *OrchestratorContext)
	SetTransientPreviousStageOutputs(tpso *TransientPreviousStageOutputs)
	GetRunningStageContext(ctx context.Context) *RunningStageContext
	GetStageTriggerError(ctx context.Context) error
	ClearRunningStageContext(ctx context.Context)
	GetStageStartTime(ctx context.Context) time.Time
	SetValidatedTransactionHashMatchState(ctx context.Context, validatedTransactionHashMatchState bool)
	ValidatedTransactionHashMatchState(ctx context.Context) bool

	// stage outputs management
	AddStageOutputs(ctx context.Context, stageOutput *StageOutput)
	ProcessStageOutputs(ctx context.Context, processFunction func(stageOutputs []*StageOutput) (unprocessedStageOutputs []*StageOutput))
	AddPersistenceOutput(ctx context.Context, stage InFlightTxStage, persistenceTime time.Time, err error)
	AddSubmitOutput(ctx context.Context, txHash *tktypes.Bytes32, submissionTime *tktypes.Timestamp, submissionOutcome SubmissionOutcome, errorReason ethclient.ErrorReason, err error)
	AddSignOutput(ctx context.Context, signedMessage []byte, txHash string, err error)
	AddGasPriceOutput(ctx context.Context, gasPriceObject *GasPriceObject, err error)
	AddConfirmationsOutput(ctx context.Context, indexedTx *blockindexer.IndexedTransaction)
	AddPanicOutput(ctx context.Context, stage InFlightTxStage)

	PersistTxState(ctx context.Context) (stage InFlightTxStage, persistenceTime time.Time, err error)
}

type NonceAssignmentIntent interface {
	Complete(ctx context.Context)
	AssignNextNonce(ctx context.Context) (uint64, error)
	Rollback(ctx context.Context)
}

type NonceCache interface {
	IntentToAssignNonce(ctx context.Context, signer string, nextNonceCB components.NextNonceCallback) (NonceAssignmentIntent, error)
}
