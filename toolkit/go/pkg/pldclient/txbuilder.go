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

package pldclient

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-signer/pkg/abi"

	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/pldapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/solutils"
	"github.com/kaleido-io/paladin/toolkit/pkg/tkmsgs"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

// General builder pattern approaches
// - Error deferred from builder until you take an

type Chainable interface {
	GetCtx() context.Context
	Error() error // if an error has happened at any point that was not returned, it is returned here
}

type TxBuilder interface {
	Chainable

	Public() TxBuilder  // a public transaction to submit directly to the base ledger
	Private() TxBuilder // a private transaction that will manage selective disclosure of state via a Paladin domain
	GetType() pldapi.TransactionType

	SolidityBuild(build *solutils.SolidityBuild) TxBuilder // sets the ABI and Bytecode from a Solidity build

	ABI(a abi.ABI) TxBuilder             // sets the ABI to use locally for function processing and pass to Paladin on TX submission - processes it locally to aid lookups and will defer an error if ABI is invalid
	ABIJSON(abiJson []byte) TxBuilder    // can result in a deferred error being stored if the ABI JSON is invalid, or the contained ABI is invalid
	ABIFunction(fn *abi.Entry) TxBuilder // sets the ABI and Function with a single call (overwrites any previous ABI)
	GetABI() abi.ABI

	Function(fn string) TxBuilder // fhe name or full signature of a function - can be left unset for a constructor
	GetFunction() string

	ABIReference(hash *tktypes.Bytes32) TxBuilder
	GetABIReference() *tktypes.Bytes32 // not calculated client set when an ABI is used - only returns non-nil if set explicitly

	IdempotencyKey(idempotencyKey string) TxBuilder // A unique identifier for your business transaction, allowing exactly-once submission over the JSON/RPC API
	GetIdempotencyKey() string

	From(from string) TxBuilder // the identifier for the signing address to use to create the signature that authorizes the transaction
	GetFrom() string

	To(to *tktypes.EthAddress) TxBuilder // the contract address to send the transaction to, or nil for a constructor
	GetTo() *tktypes.EthAddress

	Bytecode(bytecode []byte) TxBuilder // for public transaction constructors this is required (not applicable to private transactions directly - Pente is a special case handled separately)
	GetBytecode() tktypes.HexBytes

	Domain(domain string) TxBuilder // for private transaction constructors the domain must be specified. It is optional for private transactions as it will be inferred from the to address
	GetDomain() string

	Inputs(inputs any) TxBuilder // can be string and tktypes.RawJSON are interpreted as JSON, abi.ComponentValue trees can be used, and any other type will be serialized to JSON then parsed against the ABI inputs. Errors processing this input against the ABI function definition are deferred
	GetInputs() any

	JSONSerializer(serializer *abi.Serializer) TxBuilder // allows customization of how the data will be serialized into the transaction from the input (as an object or array for example)
	GetJSONSerializer() *abi.Serializer

	PublicTxOptions(opts pldapi.PublicTxOptions) TxBuilder // detailed options of how to submit the public / base ledger transaction that results from the public/private transaction
	GetPublicTxOptions() pldapi.PublicTxOptions

	Wrap(*pldapi.TransactionInput) TxBuilder // initializes a TxBuilder from an existing transaction, including setting the inputs to be the Data from the TX

	ResolveDefinition() (*abi.Entry, error)                                // resolves the function/constructor client-side against the ABI and returns the full definition
	BuildCallData() (callData tktypes.HexBytes, err error)                 // builds binary call data, useful for various low level functions on ABI
	BuildInputDataCV() (def *abi.Entry, cv *abi.ComponentValue, err error) // build the intermediate abi.ComponentValue tree for the inputs
	BuildInputDataJSON() (jsonData tktypes.RawJSON, err error)             // build the input data as JSON (object by default, with serialization options via Serializer())
	BuildTX() SendableTransaction                                          // builds the full TransactionInput object for use with Paladin - copies the TX so the builder can be re-used safely
	Send() SentTransaction                                                 // shortcut to BuildTX() then SendTX() with a chainable result (errors deferred)
}

type SendableTransaction interface {
	Chainable

	TX() *pldapi.TransactionInput // get the transaction directly to use
	Error() error                 // deferred error
	Send() SentTransaction        // sends the transaction and builds a wrapper around the returned ID, including handling idempotency key conflicts
}

type SentTransaction interface {
	Chainable

	ID() *uuid.UUID                                  // nil if there was an error
	Wait(timeout time.Duration) TransactionResult    // chainable
	Error() error                                    // get any deferred error
	GetTransaction() (*pldapi.Transaction, error)    // calls ptx_getTransaction
	GetReceipt() (*pldapi.TransactionReceipt, error) // calls ptx_getTransactionReceipt
}

type TransactionResult interface {
	Chainable

	ID() uuid.UUID
	TransactionHash() *tktypes.Bytes32   // non-nil if this made it to the chain - which is possible when error is true, for revert cases
	Error() error                        // could be a failure to submit, or an error at any point up to and including execution reversion on-chain
	Receipt() *pldapi.TransactionReceipt // if nil, then error is guaranteed to be non-nil
}

type chainable struct {
	c           *paladinClient
	ctx         context.Context
	deferredErr error
}

type txBuilder struct {
	chainable
	functions  map[string]*abi.Entry
	tx         *pldapi.TransactionInput
	serializer *abi.Serializer
	inputs     any
}

type sendableTransaction struct {
	chainable
	tx *pldapi.TransactionInput
}

type sentTransaction struct {
	chainable
	txID *uuid.UUID
}

type transactionResult struct {
	chainable
	txID    uuid.UUID
	receipt *pldapi.TransactionReceipt
}

func (wc *chainable) GetCtx() context.Context {
	return wc.ctx
}

func (wc *chainable) deferError(err error) {
	if err != nil {
		log.L(wc.GetCtx()).Errorf("deferred error: %s", err)
		if wc.deferredErr == nil {
			wc.deferredErr = err // first error wins
		}
	}
}

func (wc *chainable) Error() error {
	return wc.deferredErr
}

func (c *paladinClient) TxBuilder(ctx context.Context) TxBuilder {
	return &txBuilder{
		// Root of a chain
		chainable: chainable{
			ctx: ctx,
			c:   c,
		},
		functions: map[string]*abi.Entry{},
		tx:        &pldapi.TransactionInput{},
		// Use the default serializer unless overridden
		serializer: tktypes.StandardABISerializer(),
	}
}

func (t *txBuilder) ABI(a abi.ABI) TxBuilder {
	t.tx.ABI = a
	t.functions = map[string]*abi.Entry{}
	for _, e := range a {
		s, err := e.SignatureCtx(t.ctx)
		if err != nil {
			t.deferError(err)
			return t
		}
		if e.Name != "" && e.IsFunction() {
			for i, o := range e.Outputs {
				if o.Name == "" {
					o.Name = strconv.Itoa(i)
				}
			}
			t.functions[e.Name] = e
			t.functions[s] = e
		}
	}
	return t
}

func (t *txBuilder) ABIFunction(fn *abi.Entry) TxBuilder {
	return t.ABI(abi.ABI{fn}).Function(fn.String())
}

func (t *txBuilder) ABIJSON(abiJson []byte) TxBuilder {
	var a abi.ABI
	err := json.Unmarshal(abiJson, &a)
	if err != nil {
		t.deferError(i18n.WrapError(t.ctx, err, tkmsgs.MsgPaladinClientABIJson))
		return t
	}
	return t.ABI(a)
}

func (t *txBuilder) ABIReference(hash *tktypes.Bytes32) TxBuilder {
	t.tx.ABIReference = hash
	return t
}

func (t *txBuilder) Bytecode(b []byte) TxBuilder {
	t.tx.Bytecode = b
	return t
}

func (t *txBuilder) Domain(domain string) TxBuilder {
	t.tx.Domain = domain
	return t
}

func (t *txBuilder) From(from string) TxBuilder {
	t.tx.From = from
	return t
}

func (t *txBuilder) Function(fn string) TxBuilder {
	t.tx.Function = fn
	return t
}

func (t *txBuilder) GetABI() abi.ABI {
	return t.tx.ABI
}

func (t *txBuilder) GetABIReference() *tktypes.Bytes32 {
	return t.tx.ABIReference
}

func (t *txBuilder) GetBytecode() tktypes.HexBytes {
	return t.tx.Bytecode
}

func (t *txBuilder) GetDomain() string {
	return t.tx.Domain
}

func (t *txBuilder) GetFrom() string {
	return t.tx.From
}

func (t *txBuilder) GetFunction() string {
	return t.tx.Function
}

func (t *txBuilder) GetIdempotencyKey() string {
	return t.tx.IdempotencyKey
}

func (t *txBuilder) GetInputs() any {
	return t.inputs
}

func (t *txBuilder) GetJSONSerializer() *abi.Serializer {
	return t.serializer
}

func (t *txBuilder) GetPublicTxOptions() pldapi.PublicTxOptions {
	return t.tx.PublicTxOptions
}

func (t *txBuilder) GetTo() *tktypes.EthAddress {
	return t.tx.To
}

func (t *txBuilder) GetType() pldapi.TransactionType {
	return t.tx.Type.V()
}

func (t *txBuilder) IdempotencyKey(idempotencyKey string) TxBuilder {
	t.tx.IdempotencyKey = idempotencyKey
	return t
}

func (t *txBuilder) Inputs(inputs any) TxBuilder {
	t.inputs = inputs
	return t
}

func (t *txBuilder) JSONSerializer(serializer *abi.Serializer) TxBuilder {
	t.serializer = serializer
	return t
}

func (t *txBuilder) Private() TxBuilder {
	t.tx.Type = pldapi.TransactionTypePrivate.Enum()
	return t
}

func (t *txBuilder) Public() TxBuilder {
	t.tx.Type = pldapi.TransactionTypePublic.Enum()
	return t
}

func (t *txBuilder) PublicTxOptions(opts pldapi.PublicTxOptions) TxBuilder {
	t.tx.PublicTxOptions = opts
	return t
}

func (t *txBuilder) SolidityBuild(build *solutils.SolidityBuild) TxBuilder {
	return t.ABI(build.ABI).Bytecode(build.Bytecode)
}

func (t *txBuilder) To(to *tktypes.EthAddress) TxBuilder {
	t.tx.To = to
	return t
}

func (t *txBuilder) Wrap(tx *pldapi.TransactionInput) TxBuilder {
	t.tx = tx
	t.inputs = tx.Data
	return t
}

func (t *txBuilder) BuildTX() SendableTransaction {
	st := &sendableTransaction{
		chainable: t.chainable,
	}
	var err error
	st.tx, err = t.copyTX()
	// Check it's valid before we attempt to send (won't override any earlier error)
	st.deferError(err)
	return st
}

func (t *txBuilder) copyTX() (*pldapi.TransactionInput, error) {
	tx := *t.tx
	err := t.validateForSend()
	if err == nil {
		if tx.ABI != nil {
			// Finalize the data of the transaction in the chained sendable TX
			tx.Data, err = t.BuildInputDataJSON()
			return &tx, err
		}
		// We will just send thd data blindly as JSON
		switch tv := t.inputs.(type) {
		case nil:
			tx.Data = nil
		case []byte:
			tx.Data = tv
		case string:
			tx.Data = tktypes.RawJSON(tv)
		default:
			tx.Data, err = json.Marshal(tv)
		}
	}
	return &tx, err
}

func (t *txBuilder) Send() SentTransaction {
	return t.BuildTX().Send()
}

func (t *txBuilder) BuildCallData() (callData tktypes.HexBytes, err error) {
	var inputDataRLP []byte
	def, cv, err := t.BuildInputDataCV()
	if err == nil {
		inputDataRLP, err = cv.EncodeABIDataCtx(t.ctx)
	}
	if err == nil {
		if t.tx.To != nil {
			// function call
			var selector []byte
			selector, err = def.GenerateFunctionSelectorCtx(t.ctx)
			if err == nil {
				callData = make([]byte, len(selector)+len(inputDataRLP))
				copy(callData, selector)
				copy(callData[len(selector):], inputDataRLP)
			}
		} else {
			// constructor
			callData = make([]byte, len(t.tx.Bytecode)+len(inputDataRLP))
			copy(callData, t.tx.Bytecode)
			copy(callData[len(t.tx.Bytecode):], inputDataRLP)
		}
	}
	return callData, err
}

func (t *txBuilder) ResolveDefinition() (*abi.Entry, error) {
	if t.tx.ABI == nil {
		return nil, i18n.NewError(t.ctx, tkmsgs.MsgPaladinClientNoABISupplied)
	}
	if t.tx.To == nil {
		def := t.tx.ABI.Constructor()
		if def == nil {
			return nil, i18n.NewError(t.ctx, tkmsgs.MsgPaladinClientNoConstructor)
		}
		return def, nil
	}
	if t.tx.Function == "" {
		return nil, i18n.NewError(t.ctx, tkmsgs.MsgPaladinClientNoFunction)
	}
	def := t.functions[t.tx.Function]
	if def == nil {
		return nil, i18n.NewError(t.ctx, tkmsgs.MsgPaladinClientFunctionNotFound, t.tx.Function)
	}
	return def, nil
}

func (t *txBuilder) BuildInputDataCV() (def *abi.Entry, cv *abi.ComponentValue, err error) {
	def, err = t.ResolveDefinition()
	if err != nil {
		return nil, nil, err
	}

	typeTree, err := def.Inputs.TypeComponentTreeCtx(t.ctx)
	if err != nil {
		return nil, nil, err
	}

	if t.inputs == nil && len(typeTree.TupleChildren()) > 0 {
		return nil, nil, i18n.NewError(t.ctx, tkmsgs.MsgPaladinClientMissingInput)
	}
	var inputJSONable any
	switch input := t.inputs.(type) {
	case []any:
		inputJSONable = input
	case map[string]any:
		inputJSONable = input
	case string:
		err = json.Unmarshal([]byte(input), &inputJSONable)
	case []byte:
		err = json.Unmarshal(input, &inputJSONable)
	case tktypes.RawJSON:
		err = json.Unmarshal(input, &inputJSONable)
	case *abi.ComponentValue:
		cv = input
	default:
		var jsonInput []byte
		jsonInput, err = json.Marshal(t.inputs)
		if err == nil {
			err = json.Unmarshal(jsonInput, &inputJSONable)
		}
	}
	if err == nil && cv == nil /* might have got a CV directly */ {
		cv, err = typeTree.ParseExternalCtx(t.ctx, inputJSONable)
	}
	if err != nil {
		return nil, nil, i18n.WrapError(t.ctx, err, tkmsgs.MsgPaladinClientInvalidInput, def.SolString())
	}
	return def, cv, err
}

func (t *txBuilder) BuildInputDataJSON() (jsonData tktypes.RawJSON, err error) {
	_, cv, err := t.BuildInputDataCV()
	if err != nil {
		return nil, err
	}
	return t.serializer.SerializeJSONCtx(t.ctx, cv)
}

func (st sendableTransaction) Send() SentTransaction {
	sent := &sentTransaction{
		chainable: st.chainable,
	}
	if st.tx.From == "" {
		sent.deferError(i18n.NewError(st.ctx, tkmsgs.MsgPaladinClientMissingFrom))
	}
	if sent.deferredErr != nil {
		return sent
	}
	var err error
	var existingTX *pldapi.Transaction
	sent.txID, err = st.c.PTX().SendTransaction(st.ctx, st.tx)
	if err != nil && st.tx.IdempotencyKey != "" && strings.Contains(err.Error(), "PD012220") {
		log.L(st.ctx).Infof("Idempotency key clash for %s - checking for existing transaction: %s", st.tx.IdempotencyKey, err)
		existingTX, err = st.c.PTX().GetTransactionByIdempotencyKey(st.ctx, st.tx.IdempotencyKey)
		if err == nil && existingTX != nil {
			err = nil
			sent.txID = existingTX.ID
		}
	}
	sent.deferError(err)
	return sent
}

func (st sendableTransaction) TX() *pldapi.TransactionInput {
	return st.tx
}

func (sent *sentTransaction) GetReceipt() (*pldapi.TransactionReceipt, error) {
	if sent.deferredErr != nil {
		return nil, sent.deferredErr
	}
	return sent.c.PTX().GetTransactionReceipt(sent.ctx, *sent.txID)
}

func (sent *sentTransaction) GetTransaction() (*pldapi.Transaction, error) {
	if sent.deferredErr != nil {
		return nil, sent.deferredErr
	}
	return sent.c.PTX().GetTransaction(sent.ctx, *sent.txID)
}

func (sent *sentTransaction) ID() *uuid.UUID {
	return sent.txID
}

func (sent *sentTransaction) Wait(timeout time.Duration) TransactionResult {
	tr := &transactionResult{
		chainable: sent.chainable,
	}
	if tr.deferredErr != nil {
		return tr
	}
	tr.txID = *sent.txID
	return tr.wait(timeout)
}

func (tr *transactionResult) wait(timeout time.Duration) TransactionResult {
	// TODO: Websocket optimization

	pollingInterval := tr.c.receiptPollingInterval
	if pollingInterval > timeout {
		pollingInterval = timeout
	}

	// With HTTP we poll
	startTime := time.Now()
	ticker := time.NewTicker(pollingInterval)
	defer ticker.Stop()
	attempt := 0
	var lastErr error
	for {
		attempt++
		select {
		case <-ticker.C:
		case <-tr.ctx.Done():
			tr.deferError(i18n.WrapError(tr.ctx, lastErr, tkmsgs.MsgContextCanceled))
			return tr
		}
		tr.receipt, lastErr = tr.c.PTX().GetTransactionReceipt(tr.ctx, tr.txID)
		if lastErr != nil {
			log.L(tr.ctx).Warnf("attempt %d to get receipt %s failed: %s", attempt, tr.txID, lastErr)
		}
		// Did we get one?
		if tr.receipt != nil {
			return tr
		}
		// Check we didn't timeout
		waitTime := time.Since(startTime)
		if waitTime > timeout {
			tr.deferError(i18n.WrapError(tr.ctx, lastErr, tkmsgs.MsgPaladinClientPollTimedOut, attempt, waitTime))
			return tr
		}
	}
}

func (tr *transactionResult) ID() uuid.UUID {
	return tr.txID
}

func (tr *transactionResult) Receipt() *pldapi.TransactionReceipt {
	return tr.receipt
}

func (tr *transactionResult) TransactionHash() *tktypes.Bytes32 {
	if tr.receipt != nil {
		return tr.receipt.TransactionHash
	}
	return nil
}

func (t *txBuilder) validateForSend() error {
	if t.tx.Type == "" {
		return i18n.NewError(t.ctx, tkmsgs.MsgPaladinClientMissingType)
	}
	if t.tx.Domain == "" && t.tx.Type.V() == pldapi.TransactionTypePrivate {
		return i18n.NewError(t.ctx, tkmsgs.MsgPaladinClientNoDomain)
	}
	if t.tx.To != nil {
		if t.tx.Function == "" {
			return i18n.NewError(t.ctx, tkmsgs.MsgPaladinClientNoFunction)
		}
	} else {
		if t.tx.Function != "" {
			return i18n.NewError(t.ctx, tkmsgs.MsgPaladinClientMissingTo, t.tx.Function)
		}
		if t.tx.Type.V() == pldapi.TransactionTypePrivate && t.tx.Bytecode != nil {
			return i18n.NewError(t.ctx, tkmsgs.MsgPaladinClientBytecodeWithPriv)
		} else if t.tx.Type.V() == pldapi.TransactionTypePublic && len(t.tx.Bytecode) == 0 {
			return i18n.NewError(t.ctx, tkmsgs.MsgPaladinClientBytecodeMissing)
		}
	}
	return nil
}
