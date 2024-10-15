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

	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-signer/pkg/abi"

	"github.com/kaleido-io/paladin/toolkit/pkg/ptxapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/tkmsgs"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

type ABIFunctionClient interface {
	ABI() abi.ABI
	ABIEntry() *abi.Entry
	R(ctx context.Context) ABIFunctionRequestBuilder
}

type ABIClient interface {
	ABI() abi.ABI
	Function(ctx context.Context, nameOrFullSig string) (_ ABIFunctionClient, err error)
	MustFunction(nameOrFullSig string) ABIFunctionClient
	Constructor(ctx context.Context, bytecode tktypes.HexBytes) (_ ABIFunctionClient, err error)
	MustConstructor(bytecode tktypes.HexBytes) ABIFunctionClient
}

type ABIFunctionRequestBuilder interface {
	// Builder function
	Type(ptxapi.TransactionType) ABIFunctionRequestBuilder
	From(string) ABIFunctionRequestBuilder
	To(*tktypes.EthAddress) ABIFunctionRequestBuilder
	Bytecode([]byte) ABIFunctionRequestBuilder
	Input(any) ABIFunctionRequestBuilder
	Output(any) ABIFunctionRequestBuilder
	JSONSerializer(*abi.Serializer) ABIFunctionRequestBuilder
	PublicTxOptions(ptxapi.PublicTxOptions) ABIFunctionRequestBuilder

	// Result functions
	Definition() *abi.Entry                                    // returns the definition
	BuildCallData() (callData tktypes.HexBytes, err error)     // builds binary call data, useful for various low level functions on ABI
	BuildInputDataCV() (cv *abi.ComponentValue, err error)     // build the intermediate abi.ComponentValue tree for the inputs
	BuildInputDataJSON() (jsonData tktypes.RawJSON, err error) // build the input data as JSON (object by default, with serialization options via Serializer())
	BuildTX() (*ptxapi.TransactionInput, error)                // builds the full TransactionInput object for use with Paladin
}

type abiClient struct {
	c         *paladinClient
	abi       abi.ABI
	functions map[string]*abi.Entry
}

type abiFunctionClient struct {
	c             *paladinClient
	buildBytecode tktypes.HexBytes
	signature     string
	selector      []byte
	abi           abi.ABI
	abiEntry      *abi.Entry
	inputCount    int
	inputs        abi.TypeComponent
	outputCount   int
	outputs       abi.TypeComponent
}

type abiFunctionRequestBuilder struct {
	*abiFunctionClient
	ctx        context.Context
	tx         ptxapi.TransactionInput
	serializer *abi.Serializer
	input      any
	output     any // TODO: Implement call
}

func (c *paladinClient) ABIJSON(ctx context.Context, abiJson []byte) (ABIClient, error) {
	var a abi.ABI
	err := json.Unmarshal(abiJson, &a)
	if err != nil {
		return nil, i18n.WrapError(ctx, err, tkmsgs.MsgPaladinClientABIJson)
	}
	return c.ABI(ctx, a)
}

func (c *paladinClient) ABI(ctx context.Context, a abi.ABI) (ABIClient, error) {
	functions := map[string]*abi.Entry{}
	for _, e := range a {
		s, err := e.SignatureCtx(ctx)
		if err != nil {
			return nil, err
		}
		if e.Name != "" && e.IsFunction() {
			for i, o := range e.Outputs {
				if o.Name == "" {
					o.Name = strconv.Itoa(i)
				}
			}
			functions[e.Name] = e
			functions[s] = e
		}
	}
	return &abiClient{
		c:         c,
		abi:       a,
		functions: functions,
	}, nil
}

func (c *paladinClient) MustABIJSON(abiJson []byte) ABIClient {
	abic, err := c.ABIJSON(context.Background(), abiJson)
	if err != nil {
		panic(err)
	}
	return abic
}

func (abic *abiClient) Function(ctx context.Context, nameOrFullSig string) (_ ABIFunctionClient, err error) {
	ac := &abiFunctionClient{c: abic.c, abi: abic.abi}
	functionABI := abic.functions[nameOrFullSig]
	if functionABI == nil {
		err = i18n.NewError(ctx, tkmsgs.MsgPaladinClientFunctionNotFound, nameOrFullSig)
	}
	if err == nil {
		ac.selector, err = functionABI.GenerateFunctionSelectorCtx(ctx)
	}
	if err != nil {
		return nil, err
	}
	return ac.functionCommon(ctx, functionABI)
}

func (c *paladinClient) ABIFunction(ctx context.Context, functionABI *abi.Entry) (fc ABIFunctionClient, err error) {
	a, err := c.ABI(ctx, abi.ABI{functionABI})
	if err == nil {
		fc, err = a.Function(ctx, functionABI.Name)
	}
	return fc, err
}

func (abic *abiClient) Constructor(ctx context.Context, bytecode tktypes.HexBytes) (ABIFunctionClient, error) {
	ac := &abiFunctionClient{c: abic.c, buildBytecode: bytecode, abi: abic.abi}
	functionABI := abic.abi.Constructor()
	if functionABI == nil {
		// Default constructor
		functionABI = &abi.Entry{
			Type:    abi.Constructor,
			Inputs:  abi.ParameterArray{},
			Outputs: abi.ParameterArray{},
		}
	}
	return ac.functionCommon(ctx, functionABI)
}

func (c *paladinClient) ABIConstructor(ctx context.Context, constructorABI *abi.Entry, bytecode tktypes.HexBytes) (fc ABIFunctionClient, err error) {
	a, err := c.ABI(ctx, abi.ABI{constructorABI})
	if err == nil {
		fc, err = a.Constructor(ctx, bytecode)
	}
	return fc, err
}

func (fc *abiFunctionClient) functionCommon(ctx context.Context, functionABI *abi.Entry) (_ ABIFunctionClient, err error) {
	fc.abiEntry = functionABI
	fc.signature, err = functionABI.SignatureCtx(ctx)
	if err == nil {
		fc.inputCount = len(functionABI.Inputs)
		fc.inputs, err = functionABI.Inputs.TypeComponentTreeCtx(ctx)
	}
	if err == nil {
		fc.outputCount = len(functionABI.Outputs)
		fc.outputs, err = functionABI.Outputs.TypeComponentTreeCtx(ctx)
	}
	if err != nil {
		return nil, err
	}
	return fc, nil
}

func (abic *abiClient) MustFunction(nameOrFullSig string) ABIFunctionClient {
	ac, err := abic.Function(context.Background(), nameOrFullSig)
	if err != nil {
		panic(err)
	}
	return ac
}

func (abic *abiClient) MustConstructor(bytecode tktypes.HexBytes) ABIFunctionClient {
	ac, err := abic.Constructor(context.Background(), bytecode)
	if err != nil {
		panic(err)
	}
	return ac
}

func (abic *abiClient) ABI() abi.ABI {
	return abic.abi
}

func (fc *abiFunctionClient) ABI() abi.ABI {
	return fc.abi
}

func (fc *abiFunctionClient) ABIEntry() *abi.Entry {
	return fc.abiEntry
}

func (fc *abiFunctionClient) R(ctx context.Context) ABIFunctionRequestBuilder {
	return &abiFunctionRequestBuilder{
		ctx:               ctx,
		abiFunctionClient: fc,
		serializer:        tktypes.StandardABISerializer(),
	}
}

func (b *abiFunctionRequestBuilder) From(from string) ABIFunctionRequestBuilder {
	b.tx.From = from
	return b
}

func (b *abiFunctionRequestBuilder) To(to *tktypes.EthAddress) ABIFunctionRequestBuilder {
	b.tx.To = to
	return b
}

func (b *abiFunctionRequestBuilder) Input(input any) ABIFunctionRequestBuilder {
	b.input = input
	return b
}

func (b *abiFunctionRequestBuilder) Output(output any) ABIFunctionRequestBuilder {
	b.output = output
	return b
}

func (b *abiFunctionRequestBuilder) PublicTxOptions(opts ptxapi.PublicTxOptions) ABIFunctionRequestBuilder {
	b.tx.PublicTxOptions = opts
	return b
}

func (b *abiFunctionRequestBuilder) JSONSerializer(s *abi.Serializer) ABIFunctionRequestBuilder {
	b.serializer = s
	return b
}

func (b *abiFunctionRequestBuilder) Type(t ptxapi.TransactionType) ABIFunctionRequestBuilder {
	b.tx.Type = tktypes.Enum[ptxapi.TransactionType](t)
	return b
}

func (b *abiFunctionRequestBuilder) Bytecode(bytecode []byte) ABIFunctionRequestBuilder {
	b.tx.Bytecode = bytecode
	return b
}

func (b *abiFunctionRequestBuilder) Definition() *abi.Entry {
	return b.abiEntry
}

func (b *abiFunctionRequestBuilder) validateFromToType() error {
	if b.tx.From == "" {
		return i18n.NewError(b.ctx, tkmsgs.MsgPaladinClientMissingFrom)
	}
	if b.tx.To != nil {
		if b.selector == nil {
			return i18n.NewError(b.ctx, tkmsgs.MsgPaladinClientToWithConstructor)
		}
		if b.tx.Type.V() == ptxapi.TransactionTypePrivate && b.tx.Bytecode != nil {
			return i18n.NewError(b.ctx, tkmsgs.MsgPaladinClientBytecodeWithPriv)
		} else if b.tx.Type.V() == ptxapi.TransactionTypePublic && b.tx.Bytecode == nil {
			if len(b.buildBytecode) != 0 {
				b.tx.Bytecode = b.buildBytecode
			} else {
				return i18n.NewError(b.ctx, tkmsgs.MsgPaladinClientBytecodeMissing)
			}
		}
	} else {
		if b.selector != nil {
			return i18n.NewError(b.ctx, tkmsgs.MsgPaladinClientMissingTo)
		}
	}
	return nil
}

func (b *abiFunctionRequestBuilder) BuildInputDataCV() (cv *abi.ComponentValue, err error) {
	if b.input == nil && len(b.inputs.TupleChildren()) > 0 {
		return nil, i18n.NewError(b.ctx, tkmsgs.MsgPaladinClientMissingInput)
	}
	var inputMap map[string]any
	switch input := b.input.(type) {
	case map[string]any:
		inputMap = input
	case string:
		err = json.Unmarshal([]byte(input), &inputMap)
	case []byte:
		err = json.Unmarshal(input, &inputMap)
	case tktypes.RawJSON:
		err = json.Unmarshal(input, &inputMap)
	case *abi.ComponentValue:
		cv = input
	default:
		var jsonInput []byte
		jsonInput, err = json.Marshal(b.input)
		if err == nil {
			err = json.Unmarshal(jsonInput, &inputMap)
		}
	}
	if err == nil && cv == nil /* might have got a CV directly */ {
		cv, err = b.inputs.ParseExternalCtx(b.ctx, inputMap)
	}
	if err != nil {
		return nil, i18n.WrapError(b.ctx, err, tkmsgs.MsgPaladinClientInvalidInput)
	}
	return cv, err
}

func (b *abiFunctionRequestBuilder) BuildCallData() (callData tktypes.HexBytes, err error) {
	var inputDataRLP []byte
	cv, err := b.BuildInputDataCV()
	if err == nil {
		inputDataRLP, err = cv.EncodeABIDataCtx(b.ctx)
	}
	if err == nil {
		if b.selector != nil {
			// function call
			callData = make([]byte, len(b.selector)+len(inputDataRLP))
			copy(callData, b.selector)
			copy(callData[len(b.selector):], inputDataRLP)
		} else {
			// constructor
			callData = make([]byte, len(b.tx.Bytecode)+len(inputDataRLP))
			copy(callData, b.tx.Bytecode)
			copy(callData[len(b.tx.Bytecode):], inputDataRLP)
		}
	}
	return callData, err
}

func (b *abiFunctionRequestBuilder) BuildInputDataJSON() (jsonData tktypes.RawJSON, err error) {
	cv, err := b.BuildInputDataCV()
	if err == nil {
		jsonData, err = b.serializer.SerializeJSONCtx(b.ctx, cv)
	}
	return jsonData, err
}

func (b *abiFunctionRequestBuilder) BuildTX() (tx *ptxapi.TransactionInput, err error) {
	b.tx.Data, err = b.BuildInputDataJSON()
	if b.selector == nil {
		b.tx.Function = ""
	} else {
		b.tx.Function = b.signature
	}
	if err == nil {
		err = b.validateFromToType()
	}
	if err != nil {
		return nil, err
	}
	return &b.tx, err
}
