/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package e2e

import (
	"context"
	"fmt"
	"time"

	_ "embed"

	"github.com/google/uuid"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/kaleido-io/paladin/config/pkg/pldconf"
	nototypes "github.com/kaleido-io/paladin/domains/noto/pkg/types"
	"github.com/kaleido-io/paladin/toolkit/pkg/algorithms"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/pldclient"
	"github.com/kaleido-io/paladin/toolkit/pkg/solutils"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/kaleido-io/paladin/toolkit/pkg/verifiers"
)

//go:embed abis/NotoTrackerSimple.json
var notoTrackerSimpleBuildJSON []byte

const node1HttpURL = "http://127.0.0.1:31548"
const node2HttpURL = "http://127.0.0.1:31648"
const node3HttpURL = "http://127.0.0.1:31748"

func withTimeout[T any](do func(ctx context.Context) T) T {
	ctx, cancelCtx := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelCtx()
	return do(ctx)
}

var _ = Describe("controller", Ordered, func() {
	BeforeAll(func() {
		log.SetLevel("trace")
	})

	AfterAll(func() {
	})

	Context("Noto domain verification", func() {

		ctx := context.Background()
		rpc := map[string]pldclient.PaladinClient{}

		connectNode := func(url, name string) {
			Eventually(func() bool {
				return withTimeout(func(ctx context.Context) bool {
					pld, err := pldclient.New().HTTP(ctx, &pldconf.HTTPClientConfig{URL: url})
					if err == nil {
						queriedName, err := pld.Transport().NodeName(ctx)
						Expect(err).To(BeNil())
						Expect(queriedName).To(Equal(name))
						rpc[name] = pld
					}
					return err == nil
				})
			}).Should(BeTrue())
		}

		It("waits to connect to all three nodes", func() {
			connectNode(node1HttpURL, "node1")
			connectNode(node2HttpURL, "node2")
			connectNode(node3HttpURL, "node3")
		})

		It("checks nodes can talk to each other", func() {
			for src := range rpc {
				for dest := range rpc {
					Eventually(func() bool {
						return withTimeout(func(ctx context.Context) bool {
							verifier, err := rpc[src].PTX().ResolveVerifier(ctx, fmt.Sprintf("test@%s", dest),
								algorithms.ECDSA_SECP256K1, verifiers.ETH_ADDRESS)
							if err == nil {
								addr, err := tktypes.ParseEthAddress(verifier)
								Expect(err).To(BeNil())
								Expect(addr).ToNot(BeNil())
							}
							return err == nil
						})
					}).Should(BeTrue())
				}
			}
		})

		const notary = "notary.on@node1"
		var notoContract *tktypes.EthAddress

		It("deploys a noto", func() {
			deploy := rpc["node1"].ForABI(ctx, abi.ABI{
				{Type: abi.Constructor, Inputs: abi.ParameterArray{
					{Name: "notary", Type: "string"},
				}},
			}).
				Private().
				Domain("noto").
				Constructor().
				Inputs(&nototypes.ConstructorParams{
					Notary: notary,
				}).
				From(notary).
				Send().
				Wait(5 * time.Second)
			Expect(deploy.Error()).To(BeNil())
			Expect(deploy.Receipt().ContractAddress).ToNot(BeNil())
			notoContract = deploy.Receipt().ContractAddress
			By(fmt.Sprintf("using the contract %s deployed by TX %s", notoContract, deploy.ID()))
		})

		It("mints some notos to the notary", func() {
			txn := rpc["node1"].ForABI(ctx, nototypes.NotoABI).
				Private().
				Domain("noto").
				Function("mint").
				To(notoContract).
				Inputs(&nototypes.MintParams{
					To:     notary,
					Amount: tktypes.MustParseHexUint256("123000000000000000000"),
				}).
				From(notary).
				Send().
				Wait(5 * time.Second)
			Expect(txn.Error()).To(BeNil())
			By(fmt.Sprintf("using the Noto coins minted in TX %s", txn.ID()))
		})

		var penteContract *tktypes.EthAddress

		penteGroupABI := &abi.Parameter{
			Name: "group", Type: "tuple", Components: abi.ParameterArray{
				{Name: "salt", Type: "bytes32"},
				{Name: "members", Type: "string[]"},
			},
		}

		type penteGroupParams struct {
			Salt    tktypes.Bytes32 `json:"salt"`
			Members []string        `json:"members"`
		}

		penteConstructorABI := &abi.Entry{
			Type: abi.Constructor, Inputs: abi.ParameterArray{
				penteGroupABI,
				{Name: "evmVersion", Type: "string"},
				{Name: "endorsementType", Type: "string"},
				{Name: "externalCallsEnabled", Type: "bool"},
			},
		}

		type penteConstructorParams struct {
			Group                penteGroupParams `json:"group"`
			EVMVersion           string           `json:"evmVersion"`
			EndorsementType      string           `json:"endorsementType"`
			ExternalCallsEnabled bool             `json:"externalCallsEnabled"`
		}

		notoTrackerDeployABI := &abi.Entry{
			Type: abi.Function,
			Name: "deploy",
			Inputs: abi.ParameterArray{
				penteGroupABI,
				{Name: "bytecode", Type: "bytes"},
				{Name: "inputs", Type: "tuple", Components: abi.ParameterArray{
					{Name: "maxSupply", Type: "uint256"},
				}},
			},
		}

		type penteDeployParams struct {
			Group    penteGroupParams `json:"group"`
			Bytecode tktypes.HexBytes `json:"bytecode"`
			Inputs   any              `json:"inputs"`
		}

		penteGroupNodes1and2 := penteGroupParams{
			Salt:    tktypes.Bytes32(tktypes.RandBytes(32)), // unique salt must be shared privately to retain anonymity
			Members: []string{"bob@node1", "sally@node2"},   // these will be salted to establish the endorsement key identifiers
		}

		It("deploys a pente privacy group to node1 and node2, excluding node3", func() {

			const ENDORSEMENT_TYPE__GROUP_SCOPED_IDENTITIES = "group_scoped_identities"

			deploy := rpc["node1"].ForABI(ctx, abi.ABI{penteConstructorABI}).
				Private().
				Domain("pente").
				Constructor().
				Inputs(&penteConstructorParams{
					Group:                penteGroupNodes1and2,
					EVMVersion:           "shanghai",
					EndorsementType:      ENDORSEMENT_TYPE__GROUP_SCOPED_IDENTITIES,
					ExternalCallsEnabled: true,
				}).
				From("random." + uuid.NewString()). // anyone can submit this by design
				Send().
				Wait(5 * time.Second)
			Expect(deploy.Error()).To(BeNil())
			Expect(deploy.Receipt().ContractAddress).ToNot(BeNil())
			penteContract = deploy.Receipt().ContractAddress
			By(fmt.Sprintf("using the Pente privacy group smart contract %s deployed by TX %s", penteContract, deploy.ID()))
		})

		It("deploys a private smart contract into the privacy group", func() {

			notoTracker := solutils.MustLoadBuild(notoTrackerSimpleBuildJSON)

			type notoTrackerConstructorInputParams struct {
				MaxSupply *tktypes.HexUint256 `json:"maxSupply"`
			}

			deploy := rpc["node1"].ForABI(ctx, abi.ABI{notoTrackerDeployABI}).
				Private().
				Domain("pente").
				To(penteContract).
				Function("deploy").
				Inputs(&penteDeployParams{
					Group:    penteGroupNodes1and2,
					Bytecode: notoTracker.Bytecode,
					Inputs: notoTrackerConstructorInputParams{
						MaxSupply: tktypes.Int64ToInt256(1000000),
					},
				}).
				From("random." + uuid.NewString()). // anyone can submit this by design
				Send().
				Wait(5 * time.Second)
			Expect(deploy.Error()).To(BeNil())
			By(fmt.Sprintf("using the Pente contract %s deployed into the privacy group in TX %s", "TODO!!!!", deploy.ID()))
		})

	})
})
