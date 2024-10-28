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
	"encoding/json"
	"fmt"
	"math/big"
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
	"github.com/kaleido-io/paladin/toolkit/pkg/pldapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/pldclient"
	"github.com/kaleido-io/paladin/toolkit/pkg/query"
	"github.com/kaleido-io/paladin/toolkit/pkg/solutils"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/kaleido-io/paladin/toolkit/pkg/verifiers"
)

//go:embed abis/ERC20Simple.json
var ERC20SimpleBuildJSON []byte

//go:embed abis/NotoTrackerERC20.json
var NotoTrackerERC20BuildJSON []byte

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
		log.SetLevel("warn")
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
				From(notary).
				Inputs(&nototypes.ConstructorParams{
					Notary: notary,
				}).
				Send().
				Wait(5 * time.Second)
			Expect(deploy.Error()).To(BeNil())
			Expect(deploy.Receipt().ContractAddress).ToNot(BeNil())
			notoContract = deploy.Receipt().ContractAddress
			log.L(ctx).Warnf("using the contract %s deployed by TX %s", notoContract, deploy.ID())
		})

		var notoCoinSchemaID *tktypes.Bytes32
		It("gets the coin schema", func() {
			var schemas []*pldapi.Schema
			err := rpc["node1"].CallRPC(ctx, &schemas, "pstate_listSchemas", "noto")
			Expect(err).To(BeNil())
			for _, s := range schemas {
				if s.Signature == "type=NotoCoin(bytes32 salt,string owner,uint256 amount),labels=[owner,amount]" {
					notoCoinSchemaID = &s.ID
				}
			}
			Expect(notoCoinSchemaID).ToNot(BeNil())
		})

		logWallet := func(identity, node string) {
			var addr *tktypes.EthAddress
			err := rpc[node].CallRPC(ctx, &addr, "keymgr_resolveEthAddress", identity)
			Expect(err).To(BeNil())
			var coins []*nototypes.NotoCoinState
			err = rpc[node].CallRPC(ctx, &coins, "pstate_queryContractStates", "noto", notoContract, notoCoinSchemaID,
				query.NewQueryBuilder().Equal("owner", addr).Limit(100).Query(),
				"available")
			Expect(err).To(BeNil())
			balance := big.NewInt(0)
			summary := make([]string, len(coins))
			for ic, c := range coins {
				summary[ic] = fmt.Sprintf("%s...[%s]", c.ID.String()[0:8], c.Data.Amount.Int().Text(10))
				balance = new(big.Int).Add(balance, c.Data.Amount.Int())
			}
			log.L(ctx).Warnf("%s@%s balance=%s coins:%v", identity, node, balance, summary)
		}

		var with18Decimals = func(x int64) *tktypes.HexUint256 {
			bx := new(big.Int).Mul(
				big.NewInt(x),
				new(big.Int).Exp(big.NewInt(10), big.NewInt(18), big.NewInt(0)),
			)
			return (*tktypes.HexUint256)(bx)
		}
		It("mints some notos to bob on node1", func() {
			for _, amount := range []*tktypes.HexUint256{
				with18Decimals(15),
				with18Decimals(25), // 40
				with18Decimals(30), // 70
				with18Decimals(42), // 112
			} {
				txn := rpc["node1"].ForABI(ctx, nototypes.NotoABI).
					Private().
					Domain("noto").
					Function("mint").
					To(notoContract).
					From(notary).
					Inputs(&nototypes.MintParams{
						To:     "bob@node1",
						Amount: amount,
					}).
					Send().
					Wait(5 * time.Second)
				Expect(txn.Error()).To(BeNil())
				log.L(ctx).Warnf("using the Noto coins minted in TX %s", txn.ID())
				logWallet("bob", "node1")
			}
		})

		It("sends some notos to sally on node2", func() {
			for _, amount := range []*tktypes.HexUint256{
				with18Decimals(33), // 79
				with18Decimals(66), // 13
			} {
				txn := rpc["node1"].ForABI(ctx, nototypes.NotoABI).
					Private().
					Domain("noto").
					Function("transfer").
					To(notoContract).
					From("bob@node1").
					Inputs(&nototypes.TransferParams{
						To:     "sally@node2",
						Amount: amount,
					}).
					Send().
					Wait(5 * time.Second)
				Expect(txn.Error()).To(BeNil())
				log.L(ctx).Warnf("using the Noto coins minted in TX %s", txn.ID())
				logWallet("bob", "node1")
				logWallet("sally", "node2")
			}
		})

		pentePrivGroupComps := abi.ParameterArray{
			{Name: "salt", Type: "bytes32"},
			{Name: "members", Type: "string[]"},
		}
		penteGroupABI := &abi.Parameter{
			Name: "group", Type: "tuple", Components: pentePrivGroupComps,
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
			Group                nototypes.PentePrivateGroup `json:"group"`
			EVMVersion           string                      `json:"evmVersion"`
			EndorsementType      string                      `json:"endorsementType"`
			ExternalCallsEnabled bool                        `json:"externalCallsEnabled"`
		}

		erc20DeployABI := &abi.Entry{
			Type: abi.Function,
			Name: "deploy",
			Inputs: abi.ParameterArray{
				penteGroupABI,
				{Name: "bytecode", Type: "bytes"},
				{Name: "inputs", Type: "tuple", Components: abi.ParameterArray{
					{Name: "name", Type: "string"},
					{Name: "symbol", Type: "string"},
				}},
			},
		}

		erc20PrivateABI := abi.ABI{
			{
				Type: abi.Function,
				Name: "deploy",
				Inputs: abi.ParameterArray{
					penteGroupABI,
					{Name: "bytecode", Type: "bytes"},
					{Name: "inputs", Type: "tuple", Components: abi.ParameterArray{
						{Name: "name", Type: "string"},
						{Name: "symbol", Type: "string"},
					}},
				},
			},
			{
				Type: abi.Function,
				Name: "mint",
				Inputs: abi.ParameterArray{
					penteGroupABI,
					{Name: "inputs", Type: "tuple", Components: abi.ParameterArray{
						{Name: "to", Type: "address"},
						{Name: "amount", Type: "uint256"},
					}},
				},
			},
			{
				Type: abi.Function,
				Name: "transfer",
				Inputs: abi.ParameterArray{
					penteGroupABI,
					{Name: "inputs", Type: "tuple", Components: abi.ParameterArray{
						{Name: "to", Type: "address"},
						{Name: "value", Type: "uint256"},
					}},
				},
			},
		}

		type penteDeployParams struct {
			Group    nototypes.PentePrivateGroup `json:"group"`
			Bytecode tktypes.HexBytes            `json:"bytecode"`
			Inputs   any                         `json:"inputs"`
		}

		type penteReceipt struct {
			Receipt struct {
				ContractAddress *tktypes.EthAddress `json:"contractAddress"`
			} `json:"receipt"`
		}

		penteGroupNodes1and2 := nototypes.PentePrivateGroup{
			Salt:    tktypes.Bytes32(tktypes.RandBytes(32)), // unique salt must be shared privately to retain anonymity
			Members: []string{"bob@node1", "sally@node2"},   // these will be salted to establish the endorsement key identifiers
		}

		var penteContract *tktypes.EthAddress
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
			log.L(ctx).Warnf("using the Pente privacy group smart contract %s deployed by TX %s", penteContract, deploy.ID())
		})

		var erc20DeployID uuid.UUID
		It("deploys a vanilla ERC-20 into the the privacy group with a minter/owner", func() {

			erc20Simple := solutils.MustLoadBuild(ERC20SimpleBuildJSON)

			deploy := rpc["node1"].ForABI(ctx, erc20PrivateABI).
				Private().
				Domain("pente").
				To(penteContract).
				Function("deploy").
				Inputs(&penteDeployParams{
					Group:    penteGroupNodes1and2,
					Bytecode: erc20Simple.Bytecode,
					Inputs: map[string]any{
						"name":   "Stars",
						"symbol": "STAR",
					},
				}).
				From("seren@node1").
				Send().
				Wait(5 * time.Second)
			Expect(deploy.Error()).To(BeNil())
			log.L(ctx).Warnf("using the Pente ERC-20 contract deployed into the privacy group in TX %s", deploy.ID())
			erc20DeployID = deploy.ID()
		})

		var erc20StarsAddr *tktypes.EthAddress
		It("requests the receipt from pente to get the contract address", func() {

			domainReceiptJSON, err := rpc["node1"].PTX().GetDomainReceipt(ctx, "pente", erc20DeployID)
			Expect(err).To(BeNil())
			var pr penteReceipt
			err = json.Unmarshal(domainReceiptJSON, &pr)
			Expect(err).To(BeNil())
			erc20StarsAddr = pr.Receipt.ContractAddress
			log.L(ctx).Warnf("using the private ERC-20 in the privacy group at address %s", erc20StarsAddr)

		})

		It("mints some ERC-20 inside the the privacy group", func() {

			invoke := rpc["node1"].ForABI(ctx, erc20PrivateABI).
				Private().
				Domain("pente").
				To(penteContract).
				Function("mint").
				Inputs(&penteDeployParams{
					Group: penteGroupNodes1and2,
					Inputs: map[string]any{
						"to":     tktypes.RandAddress(),
						"amount": with18Decimals(100),
					},
				}).
				From("seren@node1").
				Send().
				Wait(5 * time.Second)
			Expect(invoke.Error()).To(BeNil())
			log.L(ctx).Warnf("using the Pente ERC-20 contract deployed into the privacy group in TX %s", invoke.ID())
			erc20DeployID = invoke.ID()
		})

		var notoTrackerDeployTX uuid.UUID
		It("deploys a noto tracker smart contract into the privacy group", func() {

			notoTracker := solutils.MustLoadBuild(NotoTrackerERC20BuildJSON)

			deploy := rpc["node1"].ForABI(ctx, abi.ABI{erc20DeployABI}).
				Private().
				Domain("pente").
				To(penteContract).
				Function("deploy").
				Inputs(&penteDeployParams{
					Group:    penteGroupNodes1and2,
					Bytecode: notoTracker.Bytecode,
					Inputs: map[string]any{
						"name":   "NOTO",
						"symbol": "NOTO",
					},
				}).
				From(notary).
				Send().
				Wait(5 * time.Second)
			Expect(deploy.Error()).To(BeNil())
			log.L(ctx).Warnf("using the Pente contract deployed into the privacy group in TX %s", deploy.ID())
			notoTrackerDeployTX = deploy.ID()
		})

		var notoTrackerAddr *tktypes.EthAddress
		It("requests the receipt from pente to get the contract address", func() {

			domainReceiptJSON, err := rpc["node1"].PTX().GetDomainReceipt(ctx, "pente", notoTrackerDeployTX)
			Expect(err).To(BeNil())
			var pr penteReceipt
			err = json.Unmarshal(domainReceiptJSON, &pr)
			Expect(err).To(BeNil())
			notoTrackerAddr = pr.Receipt.ContractAddress
			log.L(ctx).Warnf("using the private ERC-20 in the privacy group at address %s", notoTrackerAddr)

		})

		var notoPenteContractAddr *tktypes.EthAddress
		It("deploys a new noto using Pente smart contract as the notary", func() {
			deploy := rpc["node1"].ForABI(ctx, abi.ABI{
				{Type: abi.Constructor, Inputs: abi.ParameterArray{
					{Name: "notary", Type: "string"},
					{Name: "guardPublicAddress", Type: "string"},
					{Name: "guardPrivateAddress", Type: "string"},
					{Name: "guardPrivateGroup", Type: "tuple", Components: pentePrivGroupComps},
				}},
			}).
				Private().
				Domain("noto").
				Constructor().
				From(notary).
				Inputs(&nototypes.ConstructorParams{
					Notary:              notary,
					GuardPublicAddress:  penteContract,
					GuardPrivateAddress: notoTrackerAddr,
					GuardPrivateGroup:   &penteGroupNodes1and2,
				}).
				Send().
				Wait(5 * time.Second)
			Expect(deploy.Error()).To(BeNil())
			Expect(deploy.Receipt().ContractAddress).ToNot(BeNil())
			notoPenteContractAddr = deploy.Receipt().ContractAddress
			log.L(ctx).Warnf("using the combined Noto<->Pente contract %s deployed by TX %s", notoPenteContractAddr, deploy.ID())
		})

		// TODO: Needs gap closing on "private transactions triggering private transactions currently supported only in testbed"
		// It("mints some noto-pentes to bob on node1", func() {
		// 	txn := rpc["node1"].ForABI(ctx, nototypes.NotoABI).
		// 		Private().
		// 		Domain("noto").
		// 		Function("mint").
		// 		To(notoPenteContractAddr).
		// 		From(notary).
		// 		Inputs(&nototypes.MintParams{
		// 			To:     "bob@node1",
		// 			Amount: notoAmount(99),
		// 		}).
		// 		Send().
		// 		Wait(5 * time.Second)
		// 	Expect(txn.Error()).To(BeNil())
		// 	log.L(ctx).Warnf("using the Noto coins minted in TX %s", txn.ID())
		// 	logWallet("bob", "node1")
		// })
	})
})
