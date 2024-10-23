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

	"github.com/hyperledger/firefly-signer/pkg/abi"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/kaleido-io/paladin/config/pkg/pldconf"
	nototypes "github.com/kaleido-io/paladin/domains/noto/pkg/types"
	"github.com/kaleido-io/paladin/toolkit/pkg/algorithms"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/pldclient"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/kaleido-io/paladin/toolkit/pkg/verifiers"
)

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
		nodes := map[string]pldclient.PaladinClient{}

		connectNode := func(url, name string) {
			Eventually(func() bool {
				return withTimeout(func(ctx context.Context) bool {
					pld, err := pldclient.New().HTTP(ctx, &pldconf.HTTPClientConfig{URL: url})
					if err == nil {
						queriedName, err := pld.Transport().NodeName(ctx)
						Expect(err).To(BeNil())
						Expect(queriedName).To(Equal(name))
						nodes[name] = pld
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
			for src := range nodes {
				for dest := range nodes {
					Eventually(func() bool {
						return withTimeout(func(ctx context.Context) bool {
							verifier, err := nodes[src].PTX().ResolveVerifier(ctx, fmt.Sprintf("test@%s", dest),
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
			deploy := nodes["node1"].ForABI(ctx, abi.ABI{
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
				Wait(10 * time.Second)
			Expect(deploy.Error()).To(BeNil())
			Expect(deploy.Receipt().ContractAddress).ToNot(BeNil())
			notoContract = deploy.Receipt().ContractAddress
		})

		It("mints some notos to the notary", func() {
			deploy := nodes["node1"].ForABI(ctx, nototypes.NotoABI).
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
				Wait(10 * time.Second)
			Expect(deploy.Error()).To(BeNil())
			Expect(deploy.Receipt().ContractAddress).ToNot(BeNil())
		})
	})
})
