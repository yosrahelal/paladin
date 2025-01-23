package nonfungible

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/kaleido-io/paladin/domains/zeto/pkg/constants"
	corepb "github.com/kaleido-io/paladin/domains/zeto/pkg/proto"
	"github.com/kaleido-io/paladin/domains/zeto/pkg/types"
	"github.com/kaleido-io/paladin/domains/zeto/pkg/zetosigner"
	"github.com/kaleido-io/paladin/toolkit/pkg/plugintk"
	pb "github.com/kaleido-io/paladin/toolkit/pkg/prototk"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

var _ plugintk.DomainCallbacks = &testDomainCallbacksT{}

type testDomainCallbacksT struct {
	testDomainCallbacks // Embed the default test implementation
	retStates           []*pb.StoredState
	retErr              error
}

func (dc *testDomainCallbacksT) FindAvailableStates(ctx context.Context, req *pb.FindAvailableStatesRequest) (*pb.FindAvailableStatesResponse, error) {
	if dc.retErr != nil {
		return nil, dc.retErr
	}
	return &pb.FindAvailableStatesResponse{
		States: dc.retStates,
	}, nil
}

func TestPrepareInputsForTransfer(t *testing.T) {
	ctx := context.Background()

	// Create a transfer parameter with tokenID 456.
	param := &types.NonFungibleTransferParamEntry{
		To:      "recipient1",
		URI:     "",
		TokenID: (*tktypes.HexUint256)(big.NewInt(456)),
	}

	tests := []struct {
		name             string
		callbacks        *testDomainCallbacksT
		params           []*types.NonFungibleTransferParamEntry
		expectErr        bool
		errContains      string
		expectedTokens   int
		expectedStateRs  int
		expectedParamURI string
	}{
		{
			name: "success: valid state found",
			callbacks: &testDomainCallbacksT{
				retStates: []*pb.StoredState{
					{
						Id:       "state1",
						SchemaId: "schema1",
						DataJson: `{"salt": "123", "uri": "https://example.com", "owner": "0xabcdef", "tokenID": "456"}`,
					},
				},
				retErr: nil,
			},
			params:           []*types.NonFungibleTransferParamEntry{param},
			expectErr:        false,
			expectedTokens:   1,
			expectedStateRs:  1,
			expectedParamURI: "https://example.com",
		},
		{
			name: "failure: callback error",
			callbacks: &testDomainCallbacksT{
				retStates: nil,
				retErr:    fmt.Errorf("callback failure"),
			},
			params:      []*types.NonFungibleTransferParamEntry{param},
			expectErr:   true,
			errContains: "PD210032",
		},
		{
			name: "failure: no available states",
			callbacks: &testDomainCallbacksT{
				retStates: []*pb.StoredState{}, // empty result
				retErr:    nil,
			},
			params:      []*types.NonFungibleTransferParamEntry{param},
			expectErr:   true,
			errContains: "PD210033",
		},
		{
			name: "failure: invalid token JSON",
			callbacks: &testDomainCallbacksT{
				retStates: []*pb.StoredState{
					{
						Id:       "state1",
						SchemaId: "schema1",
						DataJson: `{"salt": "123", "uri": "https://example.com", "owner": "0xabcdef", "tokenID":}`,
					},
				},
				retErr: nil,
			},
			params:      []*types.NonFungibleTransferParamEntry{param},
			expectErr:   true,
			errContains: "PD210034",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Call the function under test.
			tokens, stateRefs, err := prepareInputsForTransfer(ctx, tc.callbacks, &pb.StateSchema{Id: "schema1"}, false, "queryContext", "sender1", tc.params)
			if tc.expectErr {
				require.Error(t, err, "expected error in test case %q", tc.name)
				if tc.errContains != "" {
					assert.Contains(t, err.Error(), tc.errContains)
				}
			} else {
				require.NoError(t, err, "unexpected error in test case %q", tc.name)
				assert.Len(t, tokens, tc.expectedTokens, "token count mismatch")
				assert.Len(t, stateRefs, tc.expectedStateRs, "state reference count mismatch")
				// Also, verify that each transfer parameter's URI was updated.
				for _, p := range tc.params {
					assert.Equal(t, tc.expectedParamURI, p.URI, "parameter URI was not updated correctly")
				}
			}
		})
	}
}

func TestValidateTransferParams(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name        string
		params      []*types.NonFungibleTransferParamEntry
		expectErr   bool
		errContains string
	}{
		{
			name: "valid parameter",
			params: []*types.NonFungibleTransferParamEntry{
				{
					To:      "recipient",
					URI:     "https://example.com",
					TokenID: (*tktypes.HexUint256)(big.NewInt(456)),
				},
			},
			expectErr: false,
		},
		{
			name:        "no parameters provided",
			params:      []*types.NonFungibleTransferParamEntry{},
			expectErr:   true,
			errContains: "PD210024",
		},
		{
			name: "empty To field",
			params: []*types.NonFungibleTransferParamEntry{
				{
					To:      "",
					URI:     "https://example.com",
					TokenID: (*tktypes.HexUint256)(big.NewInt(456)),
				},
			},
			expectErr:   true,
			errContains: "PD210025",
		},
		{
			name: "nil TokenID",
			params: []*types.NonFungibleTransferParamEntry{
				{
					To:      "recipient",
					URI:     "https://example.com",
					TokenID: nil,
				},
			},
			expectErr:   true,
			errContains: "PD210114",
		},
		{
			name: "zero TokenID",
			params: []*types.NonFungibleTransferParamEntry{
				{
					To:  "recipient",
					URI: "https://example.com",
					// Assuming that a tokenID equal to zero is considered invalid.
					TokenID: (*tktypes.HexUint256)(big.NewInt(0)),
				},
			},
			expectErr:   true,
			errContains: "PD210114",
		},
		{
			name: "empty URI",
			params: []*types.NonFungibleTransferParamEntry{
				{
					To:      "recipient",
					URI:     "",
					TokenID: (*tktypes.HexUint256)(big.NewInt(456)),
				},
			},
			expectErr:   true,
			errContains: "PD210115",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTransferParams(ctx, tc.params)
			if tc.expectErr {
				require.Error(t, err, "expected an error for test case %q", tc.name)
				assert.Contains(t, err.Error(), tc.errContains, "error message should contain %q", tc.errContains)
			} else {
				require.NoError(t, err, "unexpected error for test case %q", tc.name)
			}
		})
	}
}

func TestGetAlgoZetoSnarkBJJ_transferHandler(t *testing.T) {
	h := &transferHandler{
		name: "transfer",
	}
	assert.Equal(t, "domain:transfer:snark:babyjubjub", h.getAlgoZetoSnarkBJJ())
}

func TestFormatProvingRequest(t *testing.T) {
	ctx := context.Background()
	handler := &transferHandler{}

	contractAddr := tktypes.MustEthAddress("0xabc123abc123abc123abc123abc123abc123abc1")

	token := types.NewZetoNFToken(
		(*tktypes.HexUint256)(big.NewInt(1)),
		"https://input.com",
		mockPubKey(),
		big.NewInt(2),
	)

	// Prepare table-driven test cases.
	tests := []struct {
		name               string
		inputTokens        []*types.ZetoNFToken
		outputTokens       []*types.ZetoNFToken
		circuitId          string
		tokenName          string
		queryContext       string
		contractAddr       *tktypes.EthAddress
		expectErr          bool
		errContains        string
		expectedCircuitId  string
		expectedInputOwner string
	}{
		{
			name:               "success: valid input and output tokens",
			inputTokens:        []*types.ZetoNFToken{token},
			outputTokens:       []*types.ZetoNFToken{token},
			circuitId:          "circuit123",
			tokenName:          "nonfungible",
			queryContext:       "ctx1",
			contractAddr:       contractAddr,
			expectErr:          false,
			expectedCircuitId:  "circuit123",
			expectedInputOwner: "51fa904bb6142e89f85aebb2a933a879e2efd5b682021deec4f717a8dbcbbd8e",
		},
		{
			name:         "failure: empty input tokens",
			inputTokens:  []*types.ZetoNFToken{},
			outputTokens: []*types.ZetoNFToken{token},
			circuitId:    "circuit123",
			tokenName:    "nonfungible",
			queryContext: "ctx1",
			contractAddr: contractAddr,
			expectErr:    true,
			errContains:  "PD210113", // from processTokens error
		},
		{
			name:         "failure: empty output tokens",
			inputTokens:  []*types.ZetoNFToken{token},
			outputTokens: []*types.ZetoNFToken{}, // output error
			circuitId:    "circuit123",
			tokenName:    "nonfungible",
			queryContext: "ctx1",
			contractAddr: contractAddr,
			expectErr:    true,
			errContains:  "PD210113",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payloadBytes, err := handler.formatProvingRequest(ctx, tc.inputTokens, tc.outputTokens, tc.circuitId, tc.tokenName, tc.queryContext, tc.contractAddr)
			if tc.expectErr {
				require.Error(t, err, "expected error in test case %q", tc.name)
				return
			}
			require.NoError(t, err, "unexpected error in test case %q", tc.name)
			require.NotNil(t, payloadBytes, "payload should not be nil")

			// Check corepb.ProvingRequest
			var req corepb.ProvingRequest
			err = proto.Unmarshal(payloadBytes, &req)
			require.NoError(t, err, "failed to unmarshal payload")

			assert.Equal(t, tc.expectedCircuitId, req.CircuitId, "CircuitId mismatch")
			require.NotNil(t, req.Common, "Common must not be nil")
			assert.Equal(t, tc.expectedInputOwner, req.Common.InputOwner, "InputOwner mismatch")
			require.NotNil(t, req.Extras, "Extras should be set")

			// Check corepb.ProvingRequestExtras_NonFungible
			var extras corepb.ProvingRequestExtras_NonFungible
			err = proto.Unmarshal(req.Extras, &extras)
			require.NoError(t, err, "failed to unmarshal Extras")

			require.Len(t, extras.TokenIds, 1, "expected one tokenId in extras")
			require.Len(t, extras.TokenUris, 1, "expected one tokenUri in extras")
			assert.Equal(t, tc.inputTokens[0].TokenID.String(), extras.TokenIds[0], "TokenId mismatch in extras")
			assert.Equal(t, tc.inputTokens[0].URI, extras.TokenUris[0], "TokenUri mismatch in extras")
		})
	}
}

func TestPrepareState(t *testing.T) {
	ctx := context.Background()

	validOwnerStr := tktypes.MustParseHexBytes(zetosigner.EncodeBabyJubJubPublicKey(mockPubKey())).String()

	// Build a valid JSON string for a token.
	validStateJSON := fmt.Sprintf(`{
		"salt": "123",
		"uri": "https://example.com",
		"owner": "%s",
		"tokenID": "456"
	}`, validOwnerStr)

	tests := []struct {
		name               string
		stateDataJSON      string
		expectErr          bool
		errContains        string
		expectHashNonEmpty bool
	}{
		{
			name:               "success",
			stateDataJSON:      validStateJSON,
			expectErr:          false,
			expectHashNonEmpty: true,
		},
		{
			name:          "invalid JSON",
			stateDataJSON: `{"bad_json": }`,
			expectErr:     true,
			errContains:   "PD210045",
		},
		{
			name: "hash error",
			stateDataJSON: fmt.Sprintf(`{
				"salt": "123",
				"uri": "",
				"owner": "%s",
				"tokenID": "0"
			}`, validOwnerStr),
			expectErr:   true,
			errContains: "PD210046",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Construct an EndorsableState with the test JSON.
			state := &pb.EndorsableState{
				StateDataJson: tc.stateDataJSON,
			}
			hashStr, err := prepareState(ctx, state)
			if tc.expectErr {
				require.Error(t, err, "expected error for test case %q", tc.name)
				assert.Contains(t, err.Error(), tc.errContains, "error message should contain %q", tc.errContains)
			} else {
				require.NoError(t, err, "unexpected error for test case %q", tc.name)
				if tc.expectHashNonEmpty {
					assert.NotEmpty(t, hashStr, "expected non-empty hash string")
				}
			}
		})
	}
}

func dummyFindAttestationSuccess(name string, attestations []*pb.AttestationResult) *pb.AttestationResult {
	proofRes := &corepb.ProvingResponse{
		Proof: &corepb.SnarkProof{
			A: []string{"a1", "a2"},
			B: []*corepb.B_Item{
				{Items: []string{"b00", "b01"}},
				{Items: []string{"b10", "b11"}},
			},
			C: []string{"c1", "c2"},
		},
		PublicInputs: map[string]string{
			"nullifier": "n1,n2",
			"root":      "r1",
		},
	}
	payload, _ := proto.Marshal(proofRes)
	return &pb.AttestationResult{
		Name:    "sender",
		Payload: payload,
	}
}
func dummyFindAttestationFailed(string, []*pb.AttestationResult) *pb.AttestationResult { return nil }
func dummyFindAttestationBadPayload(string, []*pb.AttestationResult) *pb.AttestationResult {
	return &pb.AttestationResult{Payload: []byte("bad payload")}
}

// dummyEncodeTxData returns fixed transaction data.
func dummyEncodeTxData(ctx context.Context, transaction *pb.TransactionSpecification, transactionData ethtypes.HexBytes0xPrefix) (tktypes.HexBytes, error) {
	return []byte("txdata"), nil
}

// dummyEncodeTxDataFailed returns an error
func dummyEncodeTxDataFailed(context.Context, *pb.TransactionSpecification, ethtypes.HexBytes0xPrefix) (tktypes.HexBytes, error) {
	return nil, fmt.Errorf("dummyEncodeTxDataFailed")
}

// dummyEncodeProof returns a fixed proof map.
func dummyEncodeProof(proof *corepb.SnarkProof) map[string]interface{} {
	return map[string]interface{}{
		"pA": []string{"a1", "a2"},
		"pB": [][]string{
			{"b01", "b00"},
			{"b11", "b10"},
		},
		"pC": []string{"c1", "c2"},
	}
}

func TestPrepare(t *testing.T) {
	ctx := context.Background()

	validOwnerStr := tktypes.MustParseHexBytes(zetosigner.EncodeBabyJubJubPublicKey(mockPubKey())).String()
	validStateJSON := fmt.Sprintf(`{
		"salt": "123",
		"uri": "https://example.com",
		"owner": "%s",
		"tokenID": "456"
	}`, validOwnerStr)
	inputState := &pb.EndorsableState{StateDataJson: validStateJSON}
	outputState := &pb.EndorsableState{StateDataJson: validStateJSON}

	req := &pb.PrepareTransactionRequest{
		AttestationResult: []*pb.AttestationResult{
			{Name: "sender"},
		},
		InputStates:  []*pb.EndorsableState{inputState},
		OutputStates: []*pb.EndorsableState{outputState},
		Transaction:  &pb.TransactionSpecification{TransactionId: "0x1234"},
	}

	tests := []struct {
		name          string
		tx            *types.ParsedTransaction
		req           *pb.PrepareTransactionRequest
		expectErr     bool
		errContains   string
		nullifiers    bool
		assertionFunc func(string, []*pb.AttestationResult) *pb.AttestationResult
		encodeTxFunc  func(context.Context, *pb.TransactionSpecification, ethtypes.HexBytes0xPrefix) (tktypes.HexBytes, error)
	}{
		{
			name: "success non-nullifier",
			tx: &types.ParsedTransaction{
				Transaction: &pb.TransactionSpecification{},
				DomainConfig: &types.DomainInstanceConfig{
					TokenName: constants.TOKEN_NF_ANON,
					CircuitId: constants.CIRCUIT_NF_ANON,
				},
			},
			assertionFunc: dummyFindAttestationSuccess,
			encodeTxFunc:  dummyEncodeTxData,
			req:           req,
			expectErr:     false,
			nullifiers:    false,
		},
		{
			name: "success nullifier",
			tx: &types.ParsedTransaction{
				Transaction: &pb.TransactionSpecification{},
				DomainConfig: &types.DomainInstanceConfig{
					TokenName: constants.TOKEN_NF_ANON_NULLIFIER,
					CircuitId: constants.CIRCUIT_NF_ANON_NULLIFIER,
				},
			},
			assertionFunc: dummyFindAttestationSuccess,
			encodeTxFunc:  dummyEncodeTxData,
			req:           req,
			expectErr:     false,
			nullifiers:    true,
		},
		{
			name: "failure: missing attestation",
			tx: &types.ParsedTransaction{
				Transaction: &pb.TransactionSpecification{},
				DomainConfig: &types.DomainInstanceConfig{
					TokenName: constants.TOKEN_NF_ANON,
					CircuitId: constants.CIRCUIT_NF_ANON,
				},
			},
			req: &pb.PrepareTransactionRequest{
				AttestationResult: []*pb.AttestationResult{}, // empty attestation list.
				InputStates:       []*pb.EndorsableState{inputState},
				OutputStates:      []*pb.EndorsableState{outputState},
				Transaction:       &pb.TransactionSpecification{},
			},
			assertionFunc: dummyFindAttestationFailed,
			encodeTxFunc:  dummyEncodeTxData,
			expectErr:     true,
			errContains:   "PD210043",
		},
		{
			name: "failure: invalid attestation payload",
			tx: &types.ParsedTransaction{
				Transaction: &pb.TransactionSpecification{},
				DomainConfig: &types.DomainInstanceConfig{
					TokenName: constants.TOKEN_NF_ANON,
					CircuitId: constants.CIRCUIT_NF_ANON,
				},
			},
			req: func() *pb.PrepareTransactionRequest {
				return &pb.PrepareTransactionRequest{
					AttestationResult: []*pb.AttestationResult{},
					InputStates:       []*pb.EndorsableState{inputState},
					OutputStates:      []*pb.EndorsableState{outputState},
					Transaction:       &pb.TransactionSpecification{},
				}
			}(),
			assertionFunc: dummyFindAttestationBadPayload,
			encodeTxFunc:  dummyEncodeTxData,
			expectErr:     true,
			errContains:   "PD210044",
		},
		{
			name: "failure: failed decoding transaction data",
			tx: &types.ParsedTransaction{
				Transaction: &pb.TransactionSpecification{},
				DomainConfig: &types.DomainInstanceConfig{
					TokenName: constants.TOKEN_NF_ANON,
					CircuitId: constants.CIRCUIT_NF_ANON,
				},
			},
			req: func() *pb.PrepareTransactionRequest {
				return &pb.PrepareTransactionRequest{
					AttestationResult: []*pb.AttestationResult{},
					InputStates:       []*pb.EndorsableState{inputState},
					OutputStates:      []*pb.EndorsableState{outputState},
					Transaction:       &pb.TransactionSpecification{},
				}
			}(),
			assertionFunc: dummyFindAttestationSuccess,
			encodeTxFunc:  dummyEncodeTxDataFailed,
			expectErr:     true,
			errContains:   "PD210049",
		},
	}

	handler := &transferHandler{
		callbacks: nil,
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			findAttestationFunc = tc.assertionFunc
			encodeTransactionDataFunc = tc.encodeTxFunc
			encodeProofFunc = dummyEncodeProof

			resp, err := handler.Prepare(ctx, tc.tx, tc.req)
			if tc.expectErr {
				require.Error(t, err, "expected error in test case %q", tc.name)
				if tc.errContains != "" {
					assert.Contains(t, err.Error(), tc.errContains, "error message should contain %q", tc.errContains)
				}
			} else {
				require.NoError(t, err, "unexpected error in test case %q", tc.name)
				require.NotNil(t, resp, "response should not be nil")

				// Unmarshal function ABI and params from the response.
				var abiObj interface{}
				err = json.Unmarshal([]byte(resp.Transaction.FunctionAbiJson), &abiObj)
				require.NoError(t, err, "failed to unmarshal FunctionAbiJson")

				var params map[string]interface{}
				err = json.Unmarshal([]byte(resp.Transaction.ParamsJson), &params)
				require.NoError(t, err, "failed to unmarshal ParamsJson")

				// For non-nullifier tokens, expect "input" key.
				_, inputExists := params["input"]
				if tc.nullifiers {
					assert.False(t, inputExists, "input key should be removed for nullifier tokens")
					_, nullifierExists := params["nullifier"]
					assert.True(t, nullifierExists, "nullifier key should be present for nullifier tokens")
					_, rootExists := params["root"]
					assert.True(t, rootExists, "root key should be present for nullifier tokens")
				} else {
					assert.True(t, inputExists, "input key should be present for non-nullifier tokens")
				}

				assert.Equal(t, "0x747864617461", params["data"], "data mismatch")
				_, proofExists := params["proof"]
				assert.True(t, proofExists, "proof should be present")
			}
		})
	}
}

// ---
// For testing, we override helper functions via the transferHandlerHelpers interface.
// These helpers are overridable in the handler.

// func dummyFindVerifier(from, algo, verifierType string, resolvers []*pb.ResolvedVerifier) *pb.ResolvedVerifier {
// 	// For testing, always return a dummy resolved verifier if at least one is provided.
// 	if len(resolvers) > 0 {
// 		return &pb.ResolvedVerifier{Verifier: "dummyVerifier"}
// 	}
// 	return nil
// }

func dummyGetAlgoZetoSnarkBJJ() string {
	return "domain:test:snark:babyjubjub"
}

func dummyFormatProvingRequest(ctx context.Context, input, output []*types.ZetoNFToken, circuitId, tokenName, stateQueryContext string, contractAddress *tktypes.EthAddress) ([]byte, error) {
	// Return a dummy payload; for instance, "dummyPayload" in hex format.
	// (For demonstration, we return a fixed string.)
	return []byte("dummyPayload"), nil
}

// ---
// Dummy input state JSON used by prepareState (which is called inside processTokens).

// ---
// TestAssemble tests the Assemble method of transferHandler.
// func TestAssemble(t *testing.T) {
// 	ctx := context.Background()

// 	var validStateJSON = func() string {
// 		ownerStr := tktypes.MustParseHexBytes(zetosigner.EncodeBabyJubJubPublicKey(mockPubKey())).String()
// 		return fmt.Sprintf(`{
// 			"salt": "123",
// 			"uri": "https://example.com",
// 			"owner": "%s",
// 			"tokenID": "456"
// 		}`, ownerStr)
// 	}()

// 	// Prepare a dummy PrepareTransactionRequest.
// 	req := &pb.AssembleTransactionRequest{
// 		ResolvedVerifiers: []*pb.ResolvedVerifier{
// 			// Dummy value; our overridden findVerifier will use this.
// 			{Verifier: "dummyVerifier"},
// 		},
// 		StateQueryContext: "dummyQueryContext",
// 		Transaction: &pb.TransactionSpecification{
// 			// Provide a valid contract address in ContractInfo.
// 			ContractInfo: &pb.ContractInfo{ContractAddress: "0xABC"},
// 			From:         "0xSender",
// 		},
// 	}

// 	// Prepare a slice of transfer parameters.
// 	// These are used inside processTokens via tx.Params.
// 	params := []*types.NonFungibleTransferParamEntry{
// 		{
// 			To:      "recipient1",
// 			URI:     "dummy", // initial value; will be updated by prepareInputsForTransfer
// 			TokenID: (*tktypes.HexUint256)(big.NewInt(456)),
// 		},
// 	}

// 	// Prepare a dummy parsed transaction.
// 	tx := &types.ParsedTransaction{
// 		Transaction: &pb.TransactionSpecification{
// 			From: "0xSender",
// 		},
// 		DomainConfig: &types.DomainInstanceConfig{
// 			TokenName: "nonfungible", // non-nullifier scenario; change to a nullifier token (e.g. "anon_nullifier") to test that branch
// 			CircuitId: "circuit123",
// 		},
// 		Params: params,
// 	}

// 	// We'll create a table with two cases:
// 	// 1. Success: valid attestation is found.
// 	// 2. Failure: findVerifier returns nil (missing attestation).
// 	tests := []struct {
// 		name string
// 		tx   *types.ParsedTransaction
// 		req  *pb.AssembleTransactionRequest
// 		// Overridden helper for findVerifier: if nil, then the handler returns an error.
// 		findVerifierFunc func(string, string, string, []*pb.ResolvedVerifier) *pb.ResolvedVerifier
// 		expectErr        bool
// 		errContains      string
// 		nullifiers       bool // if true, then the token is considered a nullifier token.
// 	}{
// 		{
// 			name:             "success non-nullifier",
// 			tx:               tx,
// 			req:              req,
// 			findVerifierFunc: domain.FindVerifier,
// 			expectErr:        false,
// 			nullifiers:       false,
// 		},
// 		{
// 			name: "failure: missing sender attestation",
// 			tx:   tx,
// 			req: func() *pb.PrepareTransactionRequest {
// 				// Provide an empty resolved verifiers list so that findVerifier returns nil.
// 				newReq := *req
// 				newReq.ResolvedVerifiers = []*pb.ResolvedVerifier{}
// 				return &newReq
// 			}(),
// 			findVerifierFunc: domain.FindVerifier,
// 			expectErr:        true,
// 			errContains:      "MsgErrorResolveVerifier",
// 		},
// 	}

// 	// Instantiate a transferHandler and override its helper functions.
// 	handler := &transferHandler{
// 		callbacks: nil, // not used directly in Assemble
// 		nftSchema: &pb.StateSchema{Id: "schema1"},
// 		name:      "handlerTest",
// 		transferHandlerHelpers: transferHandlerHelpers{
// 			encodeTransactionData: dummyEncodeTxData, // not used in Assemble, but may be used in formatProvingRequest indirectly
// 			encodeProof:           dummyEncodeProof,
// 			findVerifier:          domain.FindVerifier,
// 			findAttestation:       dummyFindAttestationSuccess,
// 		},
// 	}

// 	// We also need to ensure that the functions prepareInputsForTransfer and prepareOutputsForTransfer
// 	// (which are called inside Assemble) succeed. For this test, we assume they work correctly;
// 	// they will use the input and output EndorsableStates provided in req.

// 	for _, tc := range tests {
// 		t.Run(tc.name, func(t *testing.T) {
// 			// Set tx.Params for this test case.
// 			tx.Params = params

// 			resp, err := handler.Assemble(ctx, tx, tc.req)
// 			if tc.expectErr {
// 				require.Error(t, err, "expected error in test case %q", tc.name)
// 				assert.Contains(t, err.Error(), tc.errContains, "error message should contain %q", tc.errContains)
// 			} else {
// 				require.NoError(t, err, "unexpected error in test case %q", tc.name)
// 				require.NotNil(t, resp, "response should not be nil")
// 				// Verify the assembled transaction.
// 				assert.NotEmpty(t, resp.Transaction.FunctionAbiJson, "FunctionAbiJson should not be empty")
// 				assert.NotEmpty(t, resp.Transaction.ParamsJson, "ParamsJson should not be empty")
// 				// Unmarshal the parameters JSON.
// 				var paramsMap map[string]interface{}
// 				err = json.Unmarshal([]byte(resp.Transaction.ParamsJson), &paramsMap)
// 				require.NoError(t, err, "failed to unmarshal ParamsJson")
// 				// For non-nullifier tokens, we expect the "input" key to be present.
// 				_, inputExists := paramsMap["input"]
// 				if tc.nullifiers {
// 					assert.False(t, inputExists, "input key should be removed for nullifier tokens")
// 					_, nullifierExists := paramsMap["nullifier"]
// 					assert.True(t, nullifierExists, "nullifier key should be present for nullifier tokens")
// 					_, rootExists := paramsMap["root"]
// 					assert.True(t, rootExists, "root key should be present for nullifier tokens")
// 				} else {
// 					assert.True(t, inputExists, "input key should be present for non-nullifier tokens")
// 				}
// 				// Verify that the encoded transaction data is set (dummyEncodeTxData returns "txdata", but
// 				// the function calls common.EncodeTransactionData in formatProvingRequest; our override returns "dummyPayload").
// 				assert.Equal(t, "dummyPayload", string(resp.AttestationPlan[0].Payload), "attestation payload mismatch")
// 				// Verify attestation plan.
// 				attReq := resp.AttestationPlan[0]
// 				assert.Equal(t, "sender", attReq.Name, "attestation name mismatch")
// 				assert.Equal(t, dummyGetTransferABI(""), attReq.Algorithm, "attestation algorithm mismatch")
// 				assert.Equal(t, zetosignerapi.IDEN3_PUBKEY_BABYJUBJUB_COMPRESSED_0X, attReq.VerifierType, "attestation verifier type mismatch")
// 				assert.Equal(t, zetosignerapi.PAYLOAD_DOMAIN_ZETO_SNARK, attReq.PayloadType, "attestation payload type mismatch")
// 				// Check that the party matches the sender.
// 				assert.Equal(t, tx.Transaction.From, attReq.Parties[0], "attestation party mismatch")
// 			}
// 		})
// 	}
// }

// func TestValidateParams(t *testing.T) {
// 	ctx := context.Background()
// 	h := &transferHandler{}
// 	tests := []struct {
// 		name        string
// 		params      []*types.NonFungibleTransferParams
// 		expectErr   bool
// 		errContains string
// 	}{
// 		{
// 			name: "valid parameter",
// 			params: []*types.NonFungibleTransferParams{
// 				{
// 					Transfers: []*types.NonFungibleTransferParamEntry{
// 						{
// 							To:      "recipient",
// 							URI:     "https://example.com",
// 							TokenID: (*tktypes.HexUint256)(big.NewInt(456)),
// 						},
// 					},
// 				},
// 			},
// 			expectErr: false,
// 		},
// 		{
// 			name:        "no parameters provided",
// 			params:      []*types.NonFungibleTransferParams{},
// 			expectErr:   true,
// 			errContains: "PD210024",
// 		},
// 		{
// 			name: "empty To field",
// 			params: []*types.NonFungibleTransferParams{
// 				{
// 					Transfers: []*types.NonFungibleTransferParamEntry{
// 						{
// 							To:      "",
// 							URI:     "https://example.com",
// 							TokenID: (*tktypes.HexUint256)(big.NewInt(456)),
// 						},
// 					},
// 				},
// 			},
// 			expectErr:   true,
// 			errContains: "PD210025",
// 		},
// 		{
// 			name: "nil TokenID",
// 			params: []*types.NonFungibleTransferParams{
// 				{
// 					Transfers: []*types.NonFungibleTransferParamEntry{
// 						{
// 							To:      "recipient",
// 							URI:     "https://example.com",
// 							TokenID: nil,
// 						},
// 					},
// 				},
// 			},
// 			expectErr:   true,
// 			errContains: "PD210114",
// 		},
// 	}

// 	for _, tc := range tests {
// 		t.Run(tc.name, func(t *testing.T) {
// 			p, _ := json.Marshal(tc.params)
// 			_, err := h.ValidateParams(ctx, nil, string(p))
// 			if tc.expectErr {
// 				require.Error(t, err, "expected an error for test case %q", tc.name)
// 				assert.Contains(t, err.Error(), tc.errContains, "error message should contain %q", tc.errContains)
// 			} else {
// 				require.NoError(t, err, "unexpected error for test case %q", tc.name)
// 			}
// 		})
// 	}
// }
