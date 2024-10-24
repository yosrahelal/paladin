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
import io.kaleido.paladin.testbed.Testbed;
import io.kaleido.paladin.toolkit.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class BondTest {

    private static final Logger LOGGER = LogManager.getLogger(BondTest.class);

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

    @JsonIgnoreProperties(ignoreUnknown = true)
    record NotoConstructorParamsJSON(
            @JsonProperty
            String notary,
            @JsonProperty
            String guardPublicAddress,
            @JsonProperty
            JsonHex.Address guardPrivateAddress,
            @JsonProperty
            GroupTupleJSON guardPrivateGroup
    ) {
    }

    static final JsonABI.Entry notoMintABI = JsonABI.newFunction(
            "mint",
            JsonABI.newParameters(
                    JsonABI.newParameter("to", "string"),
                    JsonABI.newParameter("amount", "uint256")
            ),
            JsonABI.newParameters()
    );

    static final JsonABI.Entry notoTransferABI = JsonABI.newFunction(
            "transfer",
            JsonABI.newParameters(
                    JsonABI.newParameter("to", "string"),
                    JsonABI.newParameter("amount", "uint256")
            ),
            JsonABI.newParameters()
    );

    static final JsonABI.Entry bondTrackerDeployABI = JsonABI.newFunction(
            "deploy",
            JsonABI.newParameters(
                    JsonABI.newTuple("group", "Group", JsonABI.newParameters(
                            JsonABI.newParameter("salt", "bytes32"),
                            JsonABI.newParameter("members", "string[]")
                    )),
                    JsonABI.newParameter("bytecode", "bytes"),
                    JsonABI.newTuple("inputs", "", JsonABI.newParameters(
                            JsonABI.newParameter("name", "string"),
                            JsonABI.newParameter("symbol", "string"),
                            JsonABI.newParameter("custodian", "address"),
                            JsonABI.newParameter("distributionFactory", "address")
                    ))
            ),
            JsonABI.newParameters()
    );

    static final JsonABI.Entry bondTrackerBalanceABI = JsonABI.newFunction(
            "balanceOf",
            JsonABI.newParameters(
                    JsonABI.newTuple("group", "Group", JsonABI.newParameters(
                            JsonABI.newParameter("salt", "bytes32"),
                            JsonABI.newParameter("members", "string[]")
                    )),
                    JsonABI.newParameter("to", "address"),
                    JsonABI.newTuple("inputs", "", JsonABI.newParameters(
                            JsonABI.newParameter("account", "address")
                    ))
            ),
            JsonABI.newParameters(
                    JsonABI.newParameter("output", "uint256")
            )
    );

    static final JsonABI.Entry bondTrackerInvestorRegistryABI = JsonABI.newFunction(
            "investorRegistry",
            JsonABI.newParameters(
                    JsonABI.newTuple("group", "Group", JsonABI.newParameters(
                            JsonABI.newParameter("salt", "bytes32"),
                            JsonABI.newParameter("members", "string[]")
                    )),
                    JsonABI.newParameter("to", "address"),
                    JsonABI.newTuple("inputs", "", JsonABI.newParameters())
            ),
            JsonABI.newParameters(
                    JsonABI.newParameter("output", "address")
            )
    );

    static final JsonABI.Entry bondTrackerSetDistributionABI = JsonABI.newFunction(
            "setDistribution",
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
    record PenteCallOutputJSON(
            @JsonProperty
            String output
    ) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    record StateSchema(
            @JsonProperty
            JsonHex.Bytes32 id
    ) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    record NotoCoin(
            @JsonProperty
            NotoCoinData data
    ) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    record NotoCoinData(
            @JsonProperty
            String owner,
            @JsonProperty
            String amount
    ) {
    }

    Testbed.PrivateContractTransaction getTransactionInfo(LinkedHashMap<String, Object> res) {
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

            String bondTrackerBytecode = ResourceLoader.jsonResourceEntryText(
                    this.getClass().getClassLoader(),
                    "contracts/private/BondTracker.sol/BondTracker.json",
                    "bytecode"
            );
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

            GroupTupleJSON issuerCustodianGroup = new GroupTupleJSON(
                    JsonHex.randomBytes32(), new String[]{"issuer", "custodian"});
            GroupTupleJSON aliceCustodianGroup = new GroupTupleJSON(
                    JsonHex.randomBytes32(), new String[]{"alice", "custodian"});

            // Create the privacy groups
            String issuerCustodianInstanceAddress = testbed.getRpcClient().request("testbed_deploy",
                    "pente",
                    new PenteConfiguration.PrivacyGroupConstructorParamsJSON(
                            issuerCustodianGroup,
                            "shanghai",
                            PenteConfiguration.ENDORSEMENT_TYPE__GROUP_SCOPED_IDENTITIES,
                            true
                    ));
            assertFalse(issuerCustodianInstanceAddress.isBlank());
            String aliceCustodianInstanceAddress = testbed.getRpcClient().request("testbed_deploy",
                    "pente",
                    new PenteConfiguration.PrivacyGroupConstructorParamsJSON(
                            aliceCustodianGroup,
                            "shanghai",
                            PenteConfiguration.ENDORSEMENT_TYPE__GROUP_SCOPED_IDENTITIES,
                            true
                    ));
            assertFalse(aliceCustodianInstanceAddress.isBlank());

            String custodianAddress = testbed.getRpcClient().request("testbed_resolveVerifier",
                    "custodian", Algorithms.ECDSA_SECP256K1, Verifiers.ETH_ADDRESS);
            String aliceAddress = testbed.getRpcClient().request("testbed_resolveVerifier",
                    "alice", Algorithms.ECDSA_SECP256K1, Verifiers.ETH_ADDRESS);

            // Deploy BondTracker to the issuer/custodian privacy group
            var tx = getTransactionInfo(
                    testbed.getRpcClient().request("testbed_invoke",
                            new PrivateContractInvoke(
                                    "issuer",
                                    JsonHex.addressFrom(issuerCustodianInstanceAddress),
                                    bondTrackerDeployABI,
                                    new HashMap<>() {{
                                        put("group", issuerCustodianGroup);
                                        put("bytecode", bondTrackerBytecode);
                                        put("inputs", new HashMap<>() {{
                                            put("name", "BOND");
                                            put("symbol", "BOND");
                                            put("custodian", custodianAddress);
                                            put("distributionFactory", tokenDistributionFactoryAddress);
                                        }});
                                    }}
                            ), true));
            var extraData = new ObjectMapper().readValue(tx.extraData(), PenteConfiguration.TransactionExtraData.class);
            var bondTrackerAddress = extraData.contractAddress();

            // Create Noto token
            // TODO: should actually be created by the issuer, with custodian as notary
            String notoInstanceAddress = testbed.getRpcClient().request("testbed_deploy",
                    "noto",
                    new NotoConstructorParamsJSON(
                            "custodian",
                            issuerCustodianInstanceAddress,
                            bondTrackerAddress,
                            issuerCustodianGroup));
            assertFalse(notoInstanceAddress.isBlank());

            // Issue bond
            // TODO: should actually be initiated by the issuer
            tx = getTransactionInfo(
                    testbed.getRpcClient().request("testbed_invoke",
                            new PrivateContractInvoke(
                                    "custodian",
                                    JsonHex.addressFrom(notoInstanceAddress),
                                    notoMintABI,
                                    new HashMap<>() {{
                                        put("to", "custodian");
                                        put("amount", 1000);
                                    }}
                            ), true));

            // Validate Noto balance
            List<JsonNode> notoStates = testbed.getRpcClient().request("pstate_queryContractStates",
                    "noto",
                    notoInstanceAddress,
                    notoSchema.id,
                    null,
                    "available");
            assertEquals(1, notoStates.size());
            var notoCoin = mapper.convertValue(notoStates.getFirst(), NotoCoin.class);
            assertEquals("1000", notoCoin.data.amount);
            assertEquals(custodianAddress, notoCoin.data.owner);

            // Validate bond tracker balance
            LinkedHashMap<String, Object> queryResult = testbed.getRpcClient().request("testbed_call",
                    new PrivateContractInvoke(
                            "issuer",
                            JsonHex.addressFrom(issuerCustodianInstanceAddress),
                            bondTrackerBalanceABI,
                            new HashMap<>() {{
                                put("group", issuerCustodianGroup);
                                put("to", bondTrackerAddress.toString());
                                put("inputs", new HashMap<>() {{
                                    put("account", custodianAddress);
                                }});
                            }}
                    ), "");
            var custodianBalance = mapper.convertValue(queryResult, PenteCallOutputJSON.class);
            assertEquals("1000", custodianBalance.output);

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
            testbed.getRpcClient().request("testbed_invoke",
                    new PrivateContractInvoke(
                            "custodian",
                            JsonHex.addressFrom(issuerCustodianInstanceAddress),
                            bondTrackerSetDistributionABI,
                            new HashMap<>() {{
                                put("group", issuerCustodianGroup);
                                put("to", bondTrackerAddress.toString());
                                put("inputs", new HashMap<>() {{
                                    put("addr", tokenDistributionAddress);
                                }});
                            }}
                    ), true);

            // Get investor registry address from bond tracker
            queryResult = testbed.getRpcClient().request("testbed_call",
                    new PrivateContractInvoke(
                            "custodian",
                            JsonHex.addressFrom(issuerCustodianInstanceAddress),
                            bondTrackerInvestorRegistryABI,
                            new HashMap<>() {{
                                put("group", issuerCustodianGroup);
                                put("to", bondTrackerAddress.toString());
                                put("inputs", new HashMap<>());
                            }}
                    ), "");
            var queryOutput = mapper.convertValue(queryResult, PenteCallOutputJSON.class);
            String investorRegistryAddress = queryOutput.output();

            // Add Alice as an allowed investor
            testbed.getRpcClient().request("testbed_invoke",
                    new PrivateContractInvoke(
                            "custodian",
                            JsonHex.addressFrom(issuerCustodianInstanceAddress),
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
            tx = getTransactionInfo(
                    testbed.getRpcClient().request("testbed_invoke",
                            new PrivateContractInvoke(
                                    "alice",
                                    JsonHex.addressFrom(aliceCustodianInstanceAddress),
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
            extraData = new ObjectMapper().readValue(tx.extraData(), PenteConfiguration.TransactionExtraData.class);
            var bondSubscriptionAddress = extraData.contractAddress();

            // Alice receives full bond distribution
            // TODO: take payment as a cash token from Alice
            // TODO: this should be done together as an Atom
            testbed.getRpcClient().request("testbed_invoke",
                    new PrivateContractInvoke(
                            "alice",
                            JsonHex.addressFrom(aliceCustodianInstanceAddress),
                            bondSubscriptionMarkReceivedABI,
                            new HashMap<>() {{
                                put("group", aliceCustodianGroup);
                                put("to", bondSubscriptionAddress);
                                put("inputs", new HashMap<>() {{
                                    put("units", 1000);
                                }});
                            }}
                    ), true);
            testbed.getRpcClient().request("testbed_invoke",
                    new PrivateContractInvoke(
                            "custodian",
                            JsonHex.addressFrom(notoInstanceAddress),
                            notoTransferABI,
                            new HashMap<>() {{
                                put("to", "alice");
                                put("amount", 1000);
                            }}
                    ), true);

            // TODO: figure out how to test negative cases (such as when Pente reverts due to a non-allowed investor)

            // Validate Noto balance
            notoStates = testbed.getRpcClient().request("pstate_queryContractStates",
                    "noto",
                    notoInstanceAddress,
                    notoSchema.id,
                    null,
                    "available");
            assertEquals(1, notoStates.size());
            notoCoin = mapper.convertValue(notoStates.getFirst(), NotoCoin.class);
            assertEquals("1000", notoCoin.data.amount);
            assertEquals(aliceAddress, notoCoin.data.owner);

            // Validate bond tracker balance
            queryResult = testbed.getRpcClient().request("testbed_call",
                    new PrivateContractInvoke(
                            "issuer",
                            JsonHex.addressFrom(issuerCustodianInstanceAddress),
                            bondTrackerBalanceABI,
                            new HashMap<>() {{
                                put("group", issuerCustodianGroup);
                                put("to", bondTrackerAddress.toString());
                                put("inputs", new HashMap<>() {{
                                    put("account", custodianAddress);
                                }});
                            }}
                    ), "");
            custodianBalance = mapper.convertValue(queryResult, PenteCallOutputJSON.class);
            queryResult = testbed.getRpcClient().request("testbed_call",
                    new PrivateContractInvoke(
                            "issuer",
                            JsonHex.addressFrom(issuerCustodianInstanceAddress),
                            bondTrackerBalanceABI,
                            new HashMap<>() {{
                                put("group", issuerCustodianGroup);
                                put("to", bondTrackerAddress.toString());
                                put("inputs", new HashMap<>() {{
                                    put("account", aliceAddress);
                                }});
                            }}
                    ), "");
            var aliceBalance = mapper.convertValue(queryResult, PenteCallOutputJSON.class);
            assertEquals("0", custodianBalance.output);
            assertEquals("1000", aliceBalance.output);
        }
    }
}
