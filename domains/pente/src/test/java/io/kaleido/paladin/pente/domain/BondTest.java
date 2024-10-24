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

package io.kaleido.paladin.pente.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.kaleido.paladin.pente.domain.PenteConfiguration.GroupTupleJSON;
import io.kaleido.paladin.pente.domain.helpers.BondTrackerHelper;
import io.kaleido.paladin.pente.domain.helpers.NotoHelper;
import io.kaleido.paladin.pente.domain.helpers.PenteHelper;
import io.kaleido.paladin.testbed.Testbed;
import io.kaleido.paladin.toolkit.*;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class BondTest {

    private final Testbed.Setup testbedSetup = new Testbed.Setup("../../core/go/db/migrations/sqlite", 5000);

    JsonHex.Address deployPenteFactory() throws Exception {
        try (Testbed deployBed = new Testbed(testbedSetup)) {
            String factoryBytecode = ResourceLoader.jsonResourceEntryText(
                    this.getClass().getClassLoader(),
                    "contracts/domains/pente/PenteFactory.sol/PenteFactory.json",
                    "bytecode"
            );
            JsonABI factoryABI = JsonABI.fromJSONResourceEntry(
                    this.getClass().getClassLoader(),
                    "contracts/domains/pente/PenteFactory.sol/PenteFactory.json",
                    "abi"
            );
            String contractAddr = deployBed.getRpcClient().request("testbed_deployBytecode",
                    "deployer",
                    factoryABI,
                    factoryBytecode,
                    new HashMap<String, String>());
            return new JsonHex.Address(contractAddr);
        }
    }

    JsonHex.Address deployNotoFactory() throws Exception {
        try (Testbed deployBed = new Testbed(testbedSetup)) {
            String factoryBytecode = ResourceLoader.jsonResourceEntryText(
                    this.getClass().getClassLoader(),
                    "contracts/domains/noto/NotoFactory.sol/NotoFactory.json",
                    "bytecode"
            );
            JsonABI factoryABI = JsonABI.fromJSONResourceEntry(
                    this.getClass().getClassLoader(),
                    "contracts/domains/noto/NotoFactory.sol/NotoFactory.json",
                    "abi"
            );
            String contractAddr = deployBed.getRpcClient().request("testbed_deployBytecode",
                    "deployer",
                    factoryABI,
                    factoryBytecode,
                    new HashMap<String, String>());
            return new JsonHex.Address(contractAddr);
        }
    }

    static final JsonABI.Entry investorRegistryAddInvestorABI = JsonABI.newFunction(
            "addInvestor",
            JsonABI.newParameters(
                    JsonABI.newTuple("group", "Group", JsonABI.newParameters(
                            JsonABI.newParameter("salt", "bytes32"),
                            JsonABI.newParameter("members", "string[]")
                    )),
                    JsonABI.newParameter("to", "address"),
                    JsonABI.newTuple("inputs", "", JsonABI.newParameters(
                            JsonABI.newParameter("addr", "address")
                    ))
            ),
            JsonABI.newParameters()
    );

    static final JsonABI.Entry bondSubscriptionDeployABI = JsonABI.newFunction(
            "deploy",
            JsonABI.newParameters(
                    JsonABI.newTuple("group", "Group", JsonABI.newParameters(
                            JsonABI.newParameter("salt", "bytes32"),
                            JsonABI.newParameter("members", "string[]")
                    )),
                    JsonABI.newParameter("bytecode", "bytes"),
                    JsonABI.newTuple("inputs", "", JsonABI.newParameters(
                            JsonABI.newParameter("distributionAddress", "address"),
                            JsonABI.newParameter("units", "uint256")
                    ))
            ),
            JsonABI.newParameters()
    );

    static final JsonABI.Entry bondSubscriptionMarkReceivedABI = JsonABI.newFunction(
            "markReceived",
            JsonABI.newParameters(
                    JsonABI.newTuple("group", "Group", JsonABI.newParameters(
                            JsonABI.newParameter("salt", "bytes32"),
                            JsonABI.newParameter("members", "string[]")
                    )),
                    JsonABI.newParameter("to", "address"),
                    JsonABI.newTuple("inputs", "", JsonABI.newParameters(
                            JsonABI.newParameter("units", "uint256")
                    ))
            ),
            JsonABI.newParameters()
    );

    @JsonIgnoreProperties(ignoreUnknown = true)
    record StateSchema(
            @JsonProperty
            JsonHex.Bytes32 id
    ) {
    }

    private static Testbed.PrivateContractTransaction getTransactionInfo(LinkedHashMap<String, Object> res) {
        return new ObjectMapper().convertValue(res, Testbed.PrivateContractTransaction.class);
    }

    @Test
    void testBond() throws Exception {
        JsonHex.Address penteFactoryAddress = deployPenteFactory();
        JsonHex.Address notoFactoryAddress = deployNotoFactory();
        try (Testbed testbed = new Testbed(testbedSetup,
                new Testbed.ConfigDomain(
                        "pente",
                        penteFactoryAddress,
                        new Testbed.ConfigPlugin("jar", "", PenteDomainFactory.class.getName()),
                        new HashMap<>()
                ),
                new Testbed.ConfigDomain(
                        "noto",
                        notoFactoryAddress,
                        new Testbed.ConfigPlugin("c-shared", "noto", ""),
                        new HashMap<>()
                )
        )) {

            var mapper = new ObjectMapper();
            List<JsonNode> notoSchemas = testbed.getRpcClient().request("pstate_listSchemas",
                    "noto");
            assertEquals(1, notoSchemas.size());
            var notoSchema = mapper.convertValue(notoSchemas.getFirst(), StateSchema.class);

            String tokenDistributionFactoryBytecode = ResourceLoader.jsonResourceEntryText(
                    this.getClass().getClassLoader(),
                    "contracts/shared/TokenDistributionFactory.sol/TokenDistributionFactory.json",
                    "bytecode"
            );
            JsonABI tokenDistributionFactoryABI = JsonABI.fromJSONResourceEntry(
                    this.getClass().getClassLoader(),
                    "contracts/shared/TokenDistributionFactory.sol/TokenDistributionFactory.json",
                    "abi"
            );
            String bondSubscriptionBytecode = ResourceLoader.jsonResourceEntryText(
                    this.getClass().getClassLoader(),
                    "contracts/private/BondSubscription.sol/BondSubscription.json",
                    "bytecode"
            );

            // Create the token distribution factory on the base ledger
            String tokenDistributionFactoryAddress = testbed.getRpcClient().request("testbed_deployBytecode",
                    "issuer",
                    tokenDistributionFactoryABI,
                    tokenDistributionFactoryBytecode,
                    new HashMap<String, String>());

            String custodianAddress = testbed.getRpcClient().request("testbed_resolveVerifier",
                    "custodian", Algorithms.ECDSA_SECP256K1, Verifiers.ETH_ADDRESS);
            String aliceAddress = testbed.getRpcClient().request("testbed_resolveVerifier",
                    "alice", Algorithms.ECDSA_SECP256K1, Verifiers.ETH_ADDRESS);

            GroupTupleJSON issuerCustodianGroup = new GroupTupleJSON(
                    JsonHex.randomBytes32(), new String[]{"issuer", "custodian"});
            GroupTupleJSON aliceCustodianGroup = new GroupTupleJSON(
                    JsonHex.randomBytes32(), new String[]{"alice", "custodian"});

            // Create the privacy groups
            var issuerCustodianInstance = PenteHelper.newPrivacyGroup(
                    "pente", testbed, issuerCustodianGroup, true);
            assertFalse(issuerCustodianInstance.address().isBlank());
            var aliceCustodianInstance = PenteHelper.newPrivacyGroup(
                    "pente", testbed, aliceCustodianGroup, true);
            assertFalse(aliceCustodianInstance.address().isBlank());

            // Deploy BondTracker to the issuer/custodian privacy group
            var bondTracker = BondTrackerHelper.deploy(issuerCustodianInstance, "issuer", new HashMap<>() {{
                put("name", "BOND");
                put("symbol", "BOND");
                put("custodian", custodianAddress);
                put("distributionFactory", tokenDistributionFactoryAddress);
            }});

            // Create Noto token
            var noto = NotoHelper.deploy("noto", testbed,
                    new NotoHelper.ConstructorParams(
                            "custodian",
                            new NotoHelper.HookParams(
                                    issuerCustodianInstance.address(),
                                    bondTracker.address(),
                                    issuerCustodianGroup),
                            false));
            assertFalse(noto.address().isBlank());

            // Issue bond
            noto.mint("issuer", "custodian", 1000);

            // Validate Noto balance
            var notoStates = noto.queryStates(notoSchema.id, null);
            assertEquals(1, notoStates.size());
            assertEquals("1000", notoStates.getFirst().data().amount());
            assertEquals(custodianAddress, notoStates.getFirst().data().owner());

            // Validate bond tracker balance
            assertEquals("1000", bondTracker.balanceOf("issuer", custodianAddress));

            // Pull the last transaction receipt
            // TODO: is there a better way to correlate this from the testbed transaction?
            List<LinkedHashMap<String, Object>> transactions = testbed.getRpcClient().request("ptx_queryTransactionReceipts",
                    new JsonQuery.Query(1, null, null));
            assertEquals(1, transactions.size());
            String lastTransactionHash = transactions.getFirst().get("transactionHash").toString();

            // Parse distribution contract address on the base ledger
            // TODO: how is this bound to the Noto token?
            String distributionSignature = "event NewDistribution(address addr)";
            List<LinkedHashMap<String, Object>> events = testbed.getRpcClient().request("bidx_decodeTransactionEvents",
                    lastTransactionHash, tokenDistributionFactoryABI, "");
            var distributionEvent = events.stream().filter(obj -> obj.get("soliditySignature").equals(distributionSignature)).findFirst();
            assertTrue(distributionEvent.isPresent());
            var eventData = mapper.convertValue(distributionEvent.get().get("data"), LinkedHashMap.class);
            var tokenDistributionAddress = eventData.get("addr");

            // Tell bond tracker about the distribution contract
            // TODO: feels slightly odd to have to tell the contract about the result of the deployment it requested
            bondTracker.setDistribution("custodian", tokenDistributionAddress.toString());

            // Add Alice as an allowed investor
            String investorRegistryAddress = bondTracker.investorRegistry("custodian");
            testbed.getRpcClient().request("testbed_invoke",
                    new PrivateContractInvoke(
                            "custodian",
                            JsonHex.addressFrom(issuerCustodianInstance.address()),
                            investorRegistryAddInvestorABI,
                            new HashMap<>() {{
                                put("group", issuerCustodianGroup);
                                put("to", investorRegistryAddress);
                                put("inputs", new HashMap<>() {{
                                    put("addr", aliceAddress);
                                }});
                            }}
                    ), true);

            // Alice deploys BondSubscription to the alice/custodian privacy group, to request subscription
            // TODO: if Alice deploys, how can custodian trust it's the correct logic?
            var tx = getTransactionInfo(
                    testbed.getRpcClient().request("testbed_invoke",
                            new PrivateContractInvoke(
                                    "alice",
                                    JsonHex.addressFrom(aliceCustodianInstance.address()),
                                    bondSubscriptionDeployABI,
                                    new HashMap<>() {{
                                        put("group", aliceCustodianGroup);
                                        put("bytecode", bondSubscriptionBytecode);
                                        put("inputs", new HashMap<>() {{
                                            put("distributionAddress", tokenDistributionAddress);
                                            put("units", 1000);
                                        }});
                                    }}
                            ), true));
            var extraData = new ObjectMapper().readValue(tx.extraData(), PenteConfiguration.TransactionExtraData.class);
            var bondSubscriptionAddress = extraData.contractAddress();

            // Alice receives full bond distribution
            // TODO: take payment as a cash token from Alice
            // TODO: this should be done together as an Atom
            testbed.getRpcClient().request("testbed_invoke",
                    new PrivateContractInvoke(
                            "alice",
                            JsonHex.addressFrom(aliceCustodianInstance.address()),
                            bondSubscriptionMarkReceivedABI,
                            new HashMap<>() {{
                                put("group", aliceCustodianGroup);
                                put("to", bondSubscriptionAddress);
                                put("inputs", new HashMap<>() {{
                                    put("units", 1000);
                                }});
                            }}
                    ), true);
            noto.transfer("custodian", "alice", 1000);

            // TODO: figure out how to test negative cases (such as when Pente reverts due to a non-allowed investor)

            // Validate Noto balance
            notoStates = noto.queryStates(notoSchema.id, null);
            assertEquals(1, notoStates.size());
            assertEquals("1000", notoStates.getFirst().data().amount());
            assertEquals(aliceAddress, notoStates.getFirst().data().owner());

            // Validate bond tracker balance
            assertEquals("0", bondTracker.balanceOf("issuer", custodianAddress));
            assertEquals("1000", bondTracker.balanceOf("issuer", aliceAddress));
        }
    }
}
