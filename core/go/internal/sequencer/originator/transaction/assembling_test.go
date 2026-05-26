/*
 * Copyright © 2026 Kaleido, Inc.
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

package transaction

import (
	"context"
	"errors"
	"testing"

	"github.com/LFDT-Paladin/paladin/core/internal/components"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/common"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/prototk"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestAction_AssembleAndSign_NoAssembleRequest(t *testing.T) {
	// Test that action_AssembleAndSign returns error when latestAssembleRequest is nil
	ctx := context.Background()
	builder := NewTransactionBuilderForTesting(t, State_Assembling)
	txn, _ := builder.BuildWithMocks()

	// Explicitly set latestAssembleRequest to nil
	txn.latestAssembleRequest = nil

	// Execute the action
	err := action_AssembleAndSign(ctx, txn, nil)

	// Verify error is returned
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "No assemble request found")
}

func Test_handleAssembleAndSign_EngineIntegrationError(t *testing.T) {
	// Test that handleAssembleAndSign queues AssembleErrorEvent when AssembleAndSign fails
	ctx := context.Background()
	builder := NewTransactionBuilderForTesting(t, State_Assembling)
	txn, mocks := builder.BuildWithMocks()

	// Ensure latestAssembleRequest is set (should be set by builder for State_Assembling)
	require.NotNil(t, txn.latestAssembleRequest, "latestAssembleRequest should be set for State_Assembling")
	req := *txn.latestAssembleRequest

	// Set up PreAssembly
	preAssembly := &components.TransactionPreAssembly{}
	txn.pt.PreAssembly = preAssembly

	// Mock AssembleAndSign to return an error
	expectedError := errors.New("assembly failed")
	mocks.EngineIntegration.On(
		"AssembleAndSign",
		mock.Anything,
		txn.pt.ID,
		preAssembly,
		mock.Anything,
		mock.Anything,
	).Return(nil, expectedError)

	// Execute the method
	txn.handleAssembleAndSign(ctx, txn.pt.ID, req, preAssembly)

	// Verify AssembleErrorEvent was emitted so coordinator can park or discard the transaction
	events := mocks.GetEmittedEvents()
	require.Len(t, events, 1, "AssembleErrorEvent should be emitted when AssembleAndSign fails")
	errorEvent, ok := events[0].(*AssembleErrorEvent)
	require.True(t, ok, "Event should be AssembleErrorEvent")
	assert.Equal(t, txn.pt.ID, errorEvent.TransactionID)
	assert.Equal(t, req.requestID, errorEvent.RequestID)
}

func Test_handleAssembleAndSign_Success_OK(t *testing.T) {
	// Test that handleAssembleAndSign emits AssembleAndSignSuccessEvent when AssembleAndSign returns OK
	ctx := context.Background()
	builder := NewTransactionBuilderForTesting(t, State_Assembling)
	txn, mocks := builder.BuildWithMocks()

	// Ensure latestAssembleRequest is set
	require.NotNil(t, txn.latestAssembleRequest, "latestAssembleRequest should be set for State_Assembling")
	req := *txn.latestAssembleRequest

	// Set up PreAssembly
	preAssembly := &components.TransactionPreAssembly{}

	// Create expected post assembly with OK result
	expectedPostAssembly := &components.TransactionPostAssembly{
		AssemblyResult: prototk.AssembleTransactionResponse_OK,
	}

	// Mock AssembleAndSign to return OK
	mocks.EngineIntegration.On(
		"AssembleAndSign",
		mock.Anything,
		txn.pt.ID,
		preAssembly,
		mock.Anything,
		mock.Anything,
	).Return(expectedPostAssembly, nil)

	// Execute the method
	txn.handleAssembleAndSign(ctx, txn.pt.ID, req, preAssembly)

	// Verify AssembleAndSignSuccessEvent was emitted
	events := mocks.GetEmittedEvents()
	require.Len(t, events, 1, "Should emit exactly one event")

	successEvent, ok := events[0].(*AssembleAndSignSuccessEvent)
	require.True(t, ok, "Event should be AssembleAndSignSuccessEvent")
	assert.Equal(t, txn.pt.ID, successEvent.TransactionID)
	assert.Equal(t, req.requestID, successEvent.RequestID)
	assert.Equal(t, expectedPostAssembly, successEvent.PostAssembly)
}

func Test_handleAssembleAndSign_Success_REVERT(t *testing.T) {
	// Test that handleAssembleAndSign emits AssembleRevertEvent when AssembleAndSign returns REVERT
	ctx := context.Background()
	builder := NewTransactionBuilderForTesting(t, State_Assembling)
	txn, mocks := builder.BuildWithMocks()

	// Ensure latestAssembleRequest is set
	require.NotNil(t, txn.latestAssembleRequest, "latestAssembleRequest should be set for State_Assembling")
	req := *txn.latestAssembleRequest

	// Set up PreAssembly
	preAssembly := &components.TransactionPreAssembly{}

	// Create expected post assembly with REVERT result
	revertReason := "transaction reverted"
	expectedPostAssembly := &components.TransactionPostAssembly{
		AssemblyResult: prototk.AssembleTransactionResponse_REVERT,
		RevertReason:   &revertReason,
	}

	// Mock AssembleAndSign to return REVERT
	mocks.EngineIntegration.On(
		"AssembleAndSign",
		mock.Anything,
		txn.pt.ID,
		preAssembly,
		mock.Anything,
		mock.Anything,
	).Return(expectedPostAssembly, nil)

	// Execute the method
	txn.handleAssembleAndSign(ctx, txn.pt.ID, req, preAssembly)

	// Verify AssembleRevertEvent was emitted
	events := mocks.GetEmittedEvents()
	require.Len(t, events, 1, "Should emit exactly one event")

	revertEvent, ok := events[0].(*AssembleRevertEvent)
	require.True(t, ok, "Event should be AssembleRevertEvent")
	assert.Equal(t, txn.pt.ID, revertEvent.TransactionID)
	assert.Equal(t, req.requestID, revertEvent.RequestID)
	assert.Equal(t, expectedPostAssembly, revertEvent.PostAssembly)
}

func Test_handleAssembleAndSign_PARK(t *testing.T) {
	// Test that handleAssembleAndSign emits AssembleParkEvent when AssembleAndSign returns PARK
	ctx := context.Background()
	builder := NewTransactionBuilderForTesting(t, State_Assembling)
	txn, mocks := builder.BuildWithMocks()

	// Ensure latestAssembleRequest is set
	require.NotNil(t, txn.latestAssembleRequest, "latestAssembleRequest should be set for State_Assembling")
	req := *txn.latestAssembleRequest

	// Set up PreAssembly
	preAssembly := &components.TransactionPreAssembly{}

	// Create expected post assembly with PARK result
	expectedPostAssembly := &components.TransactionPostAssembly{
		AssemblyResult: prototk.AssembleTransactionResponse_PARK,
	}

	// Mock AssembleAndSign to return PARK
	mocks.EngineIntegration.On(
		"AssembleAndSign",
		mock.Anything,
		txn.pt.ID,
		preAssembly,
		mock.Anything,
		mock.Anything,
	).Return(expectedPostAssembly, nil)

	// Execute the method
	txn.handleAssembleAndSign(ctx, txn.pt.ID, req, preAssembly)

	// Verify AssembleParkEvent was emitted
	events := mocks.GetEmittedEvents()
	require.Len(t, events, 1, "Should emit exactly one event")

	parkEvent, ok := events[0].(*AssembleParkEvent)
	require.True(t, ok, "Event should be AssembleParkEvent")
	assert.Equal(t, txn.pt.ID, parkEvent.TransactionID)
	assert.Equal(t, req.requestID, parkEvent.RequestID)
	assert.Equal(t, expectedPostAssembly, parkEvent.PostAssembly)
}

func Test_handleAssembleAndSign_CalledWithCorrectParameters(t *testing.T) {
	// Test that AssembleAndSign is called with correct parameters
	ctx := context.Background()
	builder := NewTransactionBuilderForTesting(t, State_Assembling)
	txn, mocks := builder.BuildWithMocks()

	// Ensure latestAssembleRequest is set
	require.NotNil(t, txn.latestAssembleRequest, "latestAssembleRequest should be set for State_Assembling")
	req := *txn.latestAssembleRequest

	// Set up PreAssembly
	preAssembly := &components.TransactionPreAssembly{
		TransactionSpecification: &prototk.TransactionSpecification{
			TransactionId: txn.pt.ID.String(),
		},
	}

	// Create expected post assembly
	expectedPostAssembly := &components.TransactionPostAssembly{
		AssemblyResult: prototk.AssembleTransactionResponse_OK,
	}

	// Mock AssembleAndSign with specific parameter expectations
	mocks.EngineIntegration.On(
		"AssembleAndSign",
		ctx,
		txn.pt.ID,
		preAssembly,
		req.stateLocksJSON,
		req.coordinatorsBlockHeight,
	).Return(expectedPostAssembly, nil)

	// Execute the method
	txn.handleAssembleAndSign(ctx, txn.pt.ID, req, preAssembly)

	// Verify AssembleAndSign was called with correct parameters
	mocks.EngineIntegration.AssertExpectations(t)

	// Verify event was emitted with correct request ID
	events := mocks.GetEmittedEvents()
	require.Len(t, events, 1, "Should emit exactly one event")
	successEvent, ok := events[0].(*AssembleAndSignSuccessEvent)
	require.True(t, ok, "Event should be AssembleAndSignSuccessEvent")
	assert.Equal(t, req.requestID, successEvent.RequestID)
}

func Test_action_AssembleAndSign_SpawnsGoroutineThatQueuesEvent(t *testing.T) {
	ctx := t.Context()

	done := make(chan struct{})
	builder := NewTransactionBuilderForTesting(t, State_Assembling).
		QueueEventsTo(func(_ context.Context, _ common.Event) { close(done) })
	txn := builder.Build()

	builder.fakeEngineIntegration.On(
		"AssembleAndSign",
		mock.Anything,
		txn.pt.ID,
		mock.Anything,
		mock.Anything,
		mock.Anything,
	).Return(&components.TransactionPostAssembly{
		AssemblyResult: prototk.AssembleTransactionResponse_OK,
	}, nil)

	err := action_AssembleAndSign(ctx, txn, nil)
	require.NoError(t, err)

	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("timed out waiting for assemble goroutine to queue event")
	}
}

func Test_action_AssembleRequestReceived_SetsDelegateAndLatestRequest(t *testing.T) {
	ctx := context.Background()
	builder := NewTransactionBuilderForTesting(t, State_Delegated)
	txn, _ := builder.BuildWithMocks()
	requestID := uuid.New()
	coordinator := "coord@node1"
	preAssembly := []byte("pre")
	event := &AssembleRequestReceivedEvent{
		BaseEvent:               BaseEvent{TransactionID: txn.pt.ID},
		RequestID:               requestID,
		Coordinator:             coordinator,
		CoordinatorsBlockHeight: 100,
		StateLocksJSON:          []byte("{}"),
		PreAssembly:             preAssembly,
	}
	err := action_AssembleRequestReceived(ctx, txn, event)
	require.NoError(t, err)
	assert.Equal(t, coordinator, txn.currentDelegate)
	require.NotNil(t, txn.latestAssembleRequest)
	assert.Equal(t, requestID, txn.latestAssembleRequest.requestID)
	assert.Equal(t, int64(100), txn.latestAssembleRequest.coordinatorsBlockHeight)
	assert.Equal(t, preAssembly, txn.latestAssembleRequest.preAssembly)
}

func Test_action_AssembleAndSignSuccess_SetsPostAssemblyAndRequestID(t *testing.T) {
	ctx := context.Background()
	builder := NewTransactionBuilderForTesting(t, State_Assembling)
	txn, _ := builder.BuildWithMocks()
	requestID := uuid.New()
	postAssembly := &components.TransactionPostAssembly{AssemblyResult: prototk.AssembleTransactionResponse_OK}
	event := &AssembleAndSignSuccessEvent{
		BaseEvent:    BaseEvent{TransactionID: txn.pt.ID},
		RequestID:    requestID,
		PostAssembly: postAssembly,
	}
	err := action_AssembleAndSignSuccess(ctx, txn, event)
	require.NoError(t, err)
	assert.Same(t, postAssembly, txn.pt.PostAssembly)
	assert.Equal(t, requestID, txn.latestFulfilledAssembleRequestID)
}

func Test_action_AssembleRevert_SetsPostAssemblyAndRequestID(t *testing.T) {
	ctx := context.Background()
	builder := NewTransactionBuilderForTesting(t, State_Assembling)
	txn, _ := builder.BuildWithMocks()
	requestID := uuid.New()
	postAssembly := &components.TransactionPostAssembly{AssemblyResult: prototk.AssembleTransactionResponse_REVERT}
	event := &AssembleRevertEvent{
		BaseEvent:    BaseEvent{TransactionID: txn.pt.ID},
		RequestID:    requestID,
		PostAssembly: postAssembly,
	}
	err := action_AssembleRevert(ctx, txn, event)
	require.NoError(t, err)
	assert.Same(t, postAssembly, txn.pt.PostAssembly)
	assert.Equal(t, requestID, txn.latestFulfilledAssembleRequestID)
}

func Test_action_AssemblePark_SetsPostAssemblyAndRequestID(t *testing.T) {
	ctx := context.Background()
	builder := NewTransactionBuilderForTesting(t, State_Assembling)
	txn, _ := builder.BuildWithMocks()
	requestID := uuid.New()
	postAssembly := &components.TransactionPostAssembly{AssemblyResult: prototk.AssembleTransactionResponse_PARK}
	event := &AssembleParkEvent{
		BaseEvent:    BaseEvent{TransactionID: txn.pt.ID},
		RequestID:    requestID,
		PostAssembly: postAssembly,
	}
	err := action_AssemblePark(ctx, txn, event)
	require.NoError(t, err)
	assert.Same(t, postAssembly, txn.pt.PostAssembly)
	assert.Equal(t, requestID, txn.latestFulfilledAssembleRequestID)
}

func Test_action_AssembleError_SetsLatestFulfilledAssembleRequestID(t *testing.T) {
	ctx := context.Background()
	builder := NewTransactionBuilderForTesting(t, State_Assembling)
	txn, _ := builder.BuildWithMocks()
	requestID := uuid.New()
	event := &AssembleErrorEvent{
		BaseEvent: BaseEvent{TransactionID: txn.pt.ID},
		RequestID: requestID,
	}
	err := action_AssembleError(ctx, txn, event)
	require.NoError(t, err)
	assert.Equal(t, requestID, txn.latestFulfilledAssembleRequestID)
}

func Test_action_SendAssembleErrorResponse_Success(t *testing.T) {
	ctx := context.Background()
	builder := NewTransactionBuilderForTesting(t, State_Endorsement_Gathering)
	txn, mocks := builder.BuildWithMocks()

	coordinator := "coordinator@node1"
	txn.currentDelegate = coordinator
	requestID := uuid.New()
	txn.latestFulfilledAssembleRequestID = requestID

	mocks.SentMessageRecorder.Reset(ctx)

	err := action_SendAssembleErrorResponse(ctx, txn, nil)
	require.NoError(t, err)
	assert.True(t, mocks.SentMessageRecorder.HasSentAssembleErrorResponse(), "SendAssembleErrorResponse should have been called")
}

func Test_action_SendAssembleErrorResponse_TransportError(t *testing.T) {
	ctx := context.Background()
	builder := NewTransactionBuilderForTesting(t, State_Endorsement_Gathering).WithMockTransportWriter()
	txn, mocks := builder.BuildWithMocks()

	coordinator := "coordinator@node1"
	txn.currentDelegate = coordinator
	requestID := uuid.New()
	txn.latestFulfilledAssembleRequestID = requestID

	expectedError := errors.New("transport error")
	mocks.TransportWriter.EXPECT().SendAssembleErrorResponse(
		mock.Anything,
		txn.GetID(),
		requestID,
		coordinator,
	).Return(expectedError)

	err := action_SendAssembleErrorResponse(ctx, txn, nil)
	assert.Error(t, err)
	assert.Equal(t, expectedError, err)
}
