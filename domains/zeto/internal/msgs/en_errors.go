// Copyright © 2024 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package msgs

import (
	"fmt"
	"strings"
	"sync"

	"github.com/hyperledger/firefly-common/pkg/i18n"
	"golang.org/x/text/language"
)

const zetoPrefix = "PD21"

var registered sync.Once
var ffe = func(key, translation string, statusHint ...int) i18n.ErrorMessageKey {
	registered.Do(func() {
		i18n.RegisterPrefix(zetoPrefix, "Zeto Domain")
	})
	if !strings.HasPrefix(key, zetoPrefix) {
		panic(fmt.Errorf("must have prefix '%s': %s", zetoPrefix, key))
	}
	return i18n.FFE(language.AmericanEnglish, key, translation, statusHint...)
}

var (
	MsgContractNotFound                    = ffe("PD210000", "Contract %s not found")
	MsgErrorDecodeBJJKey                   = ffe("PD210001", "Failed to decode babyjubjub key. %s")
	MsgErrorParseDomainConfig              = ffe("PD210002", "Failed to parse domain config json. %s")
	MsgErrorConfigZetoDomain               = ffe("PD210003", "Failed to configure Zeto domain. %s")
	MsgErrorMarshalZetoEventAbis           = ffe("PD210004", "Failed to marshal Zeto event abis. %s")
	MsgErrorValidateInitDeployParams       = ffe("PD210005", "failed to validate init deploy parameters. %s")
	MsgErrorValidatePrepDeployParams       = ffe("PD210006", "failed to validate prepare deploy parameters. %s")
	MsgErrorFindCircuitId                  = ffe("PD210007", "failed to find circuit ID based on the token name. %s")
	MsgErrorValidateInitTxSpec             = ffe("PD210008", "failed to validate init transaction spec. %s")
	MsgErrorValidateAssembleTxSpec         = ffe("PD210009", "failed to validate assemble transaction spec. %s")
	MsgErrorValidateEndorseTxParams        = ffe("PD210010", "failed to validate endorse transaction spec. %s")
	MsgErrorValidatePrepTxSpec             = ffe("PD210011", "failed to validate prepare transaction spec. %s")
	MsgErrorUnmarshalFuncAbi               = ffe("PD210012", "failed to unmarshal function abi json. %s")
	MsgErrorDecodeDomainConfig             = ffe("PD210013", "failed to decode domain config. %s")
	MsgUnknownFunction                     = ffe("PD210014", "unknown function: %s")
	MsgErrorValidateFuncParams             = ffe("PD210015", "failed to validate function params. %s")
	MsgUnexpectedFuncSignature             = ffe("PD210016", "unexpected signature for function '%s': expected='%s', actual='%s'")
	MsgErrorDecodeContractAddress          = ffe("PD210017", "failed to decode contract address. %s")
	MsgErrorAbiDecodeDomainInstanceConfig  = ffe("PD210018", "failed to abi decode domain instance config bytes. %s")
	MsgErrorNewSmt                         = ffe("PD210019", "failed to create Merkle tree for %s: %s")
	MsgErrorHandleEvents                   = ffe("PD210020", "failed to handle events %s")
	MsgErrorGetNewSmtStates                = ffe("PD210021", "failed to get new states for Merkle tree %s: %s")
	MsgErrorGetVerifier                    = ffe("PD210022", "failed to get verifier. %s")
	MsgErrorSign                           = ffe("PD210023", "failed to sign. %s")
	MsgNoTransferParams                    = ffe("PD210024", "no transfer parameters provided")
	MsgNoParamTo                           = ffe("PD210025", "parameter 'to' is required")
	MsgNoParamAmount                       = ffe("PD210026", "parameter 'amount' is required")
	MsgParamAmountGtZero                   = ffe("PD210027", "parameter 'amount' must be greater than 0")
	MsgErrorParseTxId                      = ffe("PD210028", "failed to parse transaction id. %s")
	MsgErrorMarshalZetoCoinSchemaAbi       = ffe("PD210029", "failed to marshal Zeto Coin schema abi. %s")
	MsgErrorMarshalMerkleTreeRootSchemaAbi = ffe("PD210030", "failed to marshal Merkle Tree Root schema abi. %s")
	MsgErrorMarshalMerkleTreeNodeSchemaAbi = ffe("PD210031", "failed to marshal Merkle Tree Node schema abi. %s")
	MsgErrorQueryAvailCoins                = ffe("PD210032", "failed to query the state store for available coins. %s")
	MsgInsufficientFunds                   = ffe("PD210033", "insufficient funds (available=%s)")
	MsgInvalidCoin                         = ffe("PD210034", "coin %s is invalid: %s")
	MsgMaxCoinsReached                     = ffe("PD210035", "Need more than maximum number (%d) of coins to fulfill the transfer amount total")
	MsgErrorResolveVerifier                = ffe("PD210036", "failed to resolve verifier: %s")
	MsgErrorLoadOwnerPubKey                = ffe("PD210037", "failed load owner public key. %s")
	MsgErrorCreateNewState                 = ffe("PD210038", "failed to create new state. %s")
	MsgErrorPrepTxInputs                   = ffe("PD210039", "failed to prepare transaction inputs. %s")
	MsgErrorPrepTxOutputs                  = ffe("PD210040", "failed to prepare transaction outputs. %s")
	MsgErrorPrepTxChange                   = ffe("PD210041", "failed to prepare outputs for change coins. %s")
	MsgErrorFormatProvingReq               = ffe("PD210042", "failed to format proving request. %s")
	MsgErrorFindSenderAttestation          = ffe("PD210043", "did not find 'sender' attestation")
	MsgErrorUnmarshalProvingRes            = ffe("PD210044", "failed to unmarshal proving response. %s")
	MsgErrorParseInputStates               = ffe("PD210045", "failed to parse input states. %s")
	MsgErrorHashInputState                 = ffe("PD210046", "failed to create Poseidon hash for an input coin. %s")
	MsgErrorParseOutputStates              = ffe("PD210047", "failed to parse output states. %s")
	MsgErrorHashOutputState                = ffe("PD210048", "failed to create Poseidon hash for an output coin. %s")
	MsgErrorEncodeTxData                   = ffe("PD210049", "failed to encode transaction data. %s")
	MsgErrorMarshalPrepedParams            = ffe("PD210050", "failed to marshal prepared params to JSON. %s")
	MsgErrorFindTokenAbi                   = ffe("PD210051", "failed to find abi for the token contract %s. %s")
	MsgErrorGenerateMTP                    = ffe("PD210052", "failed to generate merkle proofs. %s")
	MsgErrorMarshalExtraObj                = ffe("PD210053", "failed to marshal the extras object in the proving request. %s")
	MsgErrorNewLeafNode                    = ffe("PD210054", "failed to create new leaf node. %s")
	MsgErrorQueryLeafNode                  = ffe("PD210055", "failed to query the smt DB for leaf node (ref=%s). %s")
	MsgErrorNewNodeIndex                   = ffe("PD210056", "failed to create new node index from hash. %s")
	MsgErrorHashMismatch                   = ffe("PD210057", "coin (ref=%s) found in the merkle tree but the persisted hash %s (index=%s) did not match the expected hash %s (index=%s)")
	MsgErrorConvertToCircomProof           = ffe("PD210058", "failed to convert to circom verifier proof. %s")
	MsgErrorUnmarshalLockProofParams       = ffe("PD210059", "failed to unmarshal lockProof parameters. %s")
	MsgErrorDecodeTransferCall             = ffe("PD210060", "failed to decode the transfer call. %s")
	MsgErrorUpdateSMT                      = ffe("PD210061", "failed to update merkle tree for the %s event. %s")
	MsgErrorAddLeafNode                    = ffe("PD210062", "failed to add leaf node. %s")
	MsgErrorNewStateFromCommittedRoot      = ffe("PD210063", "failed to create new state from committed merkle tree root node. %s")
	MsgErrorNewStateFromCommittedNode      = ffe("PD210064", "failed to create new state from committed merkle tree node. %s")
	MsgErrorQueryAvailStates               = ffe("PD210065", "failed to find available states for the merkle tree. %s")
	MsgErrorUnmarshalRootIdx               = ffe("PD210066", "failed to unmarshal root node index. %s")
	MsgErrorUnmarshalSMTNode               = ffe("PD210067", "failed to unmarshal Merkle Tree Node from state json. %s")
	MsgErrorParseNodeRef                   = ffe("PD210068", "failed to parse node reference. %s")
	MsgErrorHashSMTNode                    = ffe("PD210069", "failed to hash merkle tree node. %s")
	MsgErrorParseRootNodeIdx               = ffe("PD210070", "failed to parse root node index. %s")
	MsgErrorUpsertRootNode                 = ffe("PD210071", "failed to upsert root node. %s")
	MsgInvalidCompressedPubkeyLen          = ffe("PD210072", "invalid compressed public key length: %d")
	MsgInvalidPrivkeyLen                   = ffe("PD210073", "invalid key length: %d")
	MsgInvalidConfigCircuitRoot            = ffe("PD210074", "circuits root must be set via the configuration file")
	MsgInvalidConfigProvingKeysRoot        = ffe("PD210075", "proving keys root must be set via the configuration file")
	MsgErrorUnmarshalProvingReqExtras      = ffe("PD210076", "failed to unmarshal proving request extras for circuit %s. %s")
	MsgErrorParseEncNonce                  = ffe("PD210077", "failed to parse encryption nonce")
	MsgErrorGenerateRandBytes              = ffe("PD210078", "failed to generate random bytes for encryption key. %s")
	MsgErrorCalcNullifier                  = ffe("PD210079", "failed to calculate nullifier. %s")
	MsgErrorDecodeRootExtras               = ffe("PD210080", "failed to decode root value in extras")
	MsgErrorDecodeMTPNodeExtras            = ffe("PD210081", "failed to decode node in merkle proof in extras")
	MsgErrorParseInputSalt                 = ffe("PD210082", "failed to parse input salt")
	MsgErrorParseOutputSalt                = ffe("PD210083", "failed to parse output salt")
	MsgErrorParseInputCommitment           = ffe("PD210084", "failed to parse input commitment")
)
