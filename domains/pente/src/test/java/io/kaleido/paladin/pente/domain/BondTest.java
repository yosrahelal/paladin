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
import io.kaleido.paladin.pente.domain.helpers.BondSubscriptionHelper;
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

    @JsonIgnoreProperties(ignoreUnknown = true)
    record StateSchema(
            @JsonProperty
            JsonHex.Bytes32 id
    ) {
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

            // Create the token distribution factory on the base ledger
            String tokenDistributionFactoryAddress = testbed.getRpcClient().request("testbed_deployBytecode",
                    "issuer",
                    tokenDistributionFactoryABI,
                    tokenDistributionFactoryBytecode,
                    new HashMap<String, String>());

            String cashIssuer = "cashIssuer";
            String bondIssuer = "bondIssuer";
            String bondCustodian = "bondCustodian";
            String alice = "alice";

            String custodianAddress = testbed.getRpcClient().request("testbed_resolveVerifier",
                    bondCustodian, Algorithms.ECDSA_SECP256K1, Verifiers.ETH_ADDRESS);
            String aliceAddress = testbed.getRpcClient().request("testbed_resolveVerifier",
                    alice, Algorithms.ECDSA_SECP256K1, Verifiers.ETH_ADDRESS);

            GroupTupleJSON issuerCustodianGroup = new GroupTupleJSON(
                    JsonHex.randomBytes32(), new String[]{bondIssuer, bondCustodian});
            GroupTupleJSON aliceCustodianGroup = new GroupTupleJSON(
                    JsonHex.randomBytes32(), new String[]{alice, bondCustodian});

            // Create the privacy groups
            var issuerCustodianInstance = PenteHelper.newPrivacyGroup(
                    "pente", testbed, issuerCustodianGroup, true);
            assertFalse(issuerCustodianInstance.address().isBlank());
            var aliceCustodianInstance = PenteHelper.newPrivacyGroup(
                    "pente", testbed, aliceCustodianGroup, true);
            assertFalse(aliceCustodianInstance.address().isBlank());

            // Deploy BondTracker to the issuer/custodian privacy group
            var bondTracker = BondTrackerHelper.deploy(issuerCustodianInstance, bondIssuer, new HashMap<>() {{
                put("name", "BOND");
                put("symbol", "BOND");
                put("custodian", custodianAddress);
                put("distributionFactory", tokenDistributionFactoryAddress);
            }});

            // Create Noto tokens (bond and cash)
            var notoBond = NotoHelper.deploy("noto", testbed,
                    new NotoHelper.ConstructorParams(
                            bondCustodian,
                            new NotoHelper.HookParams(
                                    issuerCustodianInstance.address(),
                                    bondTracker.address(),
                                    issuerCustodianGroup),
                            false));
            assertFalse(notoBond.address().isBlank());
            var notoCash = NotoHelper.deploy("noto", testbed,
                    new NotoHelper.ConstructorParams(
                            cashIssuer,
                            null,
                            true));
            assertFalse(notoCash.address().isBlank());

            // Issue cash to investors
            notoCash.mint(cashIssuer, alice, 100000);

            // Issue bond to custodian
            notoBond.mint(bondIssuer, bondCustodian, 1000);

            // Validate Noto balances
            var notoCashStates = notoCash.queryStates(notoSchema.id, null);
            assertEquals(1, notoCashStates.size());
            assertEquals("100000", notoCashStates.getFirst().data().amount());
            assertEquals(aliceAddress, notoCashStates.getFirst().data().owner());
            var notoBondStates = notoBond.queryStates(notoSchema.id, null);
            assertEquals(1, notoBondStates.size());
            assertEquals("1000", notoBondStates.getFirst().data().amount());
            assertEquals(custodianAddress, notoBondStates.getFirst().data().owner());

            // Validate bond tracker balance
            assertEquals("1000", bondTracker.balanceOf(bondIssuer, custodianAddress));

            // Pull the last transaction receipt (for the bond mint)
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
            bondTracker.setDistribution(bondCustodian, tokenDistributionAddress.toString());

            // Add Alice as an allowed investor
            var investorRegistry = bondTracker.investorRegistry(bondCustodian);
            investorRegistry.addInvestor(bondCustodian, aliceAddress);

            // Alice deploys BondSubscription to the alice/custodian privacy group, to request subscription
            // TODO: if Alice deploys, how can custodian trust it's the correct logic?
            var bondSubscription = BondSubscriptionHelper.deploy(aliceCustodianInstance, alice, new HashMap<>() {{
                put("distributionAddress", tokenDistributionAddress);
                put("units", 1000);
            }});

            // Alice receives full bond distribution
            // TODO: this should be done together as an Atom
            bondSubscription.markReceived(alice, 1000);
            notoBond.transfer(bondCustodian, alice, 1000);
            notoCash.transfer(alice, bondCustodian, 1000);

            // TODO: figure out how to test negative cases (such as when Pente reverts due to a non-allowed investor)

            // Validate Noto balance
            notoCashStates = notoCash.queryStates(notoSchema.id, null);
            assertEquals(2, notoCashStates.size());
            assertEquals("1000", notoCashStates.get(0).data().amount());
            assertEquals(custodianAddress, notoCashStates.get(0).data().owner());
            assertEquals("99000", notoCashStates.get(1).data().amount());
            assertEquals(aliceAddress, notoCashStates.get(1).data().owner());
            notoBondStates = notoBond.queryStates(notoSchema.id, null);
            assertEquals(1, notoBondStates.size());
            assertEquals("1000", notoBondStates.getFirst().data().amount());
            assertEquals(aliceAddress, notoBondStates.getFirst().data().owner());

            // Validate bond tracker balance
            assertEquals("0", bondTracker.balanceOf(bondIssuer, custodianAddress));
            assertEquals("1000", bondTracker.balanceOf(bondIssuer, aliceAddress));
        }
    }
}
