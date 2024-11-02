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

package io.kaleido.paladin.pente.domain.helpers;


import com.fasterxml.jackson.databind.JsonNode;
import io.kaleido.paladin.testbed.Testbed;


import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.kaleido.paladin.pente.domain.PenteConfiguration.GroupTupleJSON;
import io.kaleido.paladin.toolkit.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;

public class NotoHelper {
    final String domainName;
    final Testbed testbed;
    final String address;

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ConstructorParams(
            @JsonProperty
            String notary,
            @JsonProperty
            HookParams hooks,
            @JsonProperty
            boolean restrictMinting
    ) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record HookParams(
            @JsonProperty
            String publicAddress,
            @JsonProperty
            JsonHex.Address privateAddress,
            @JsonProperty
            GroupTupleJSON privateGroup
    ) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record NotoCoin(
            @JsonProperty
            NotoCoinData data
    ) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record NotoCoinData(
            @JsonProperty
            String owner,
            @JsonProperty
            String amount
    ) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ApproveExtraParams(
            @JsonProperty
            JsonHex.Bytes data
    ) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record NotoPublicTransaction(
            @JsonProperty
            JsonABI.Entry functionABI,
            @JsonProperty
            JsonNode paramsJSON,
            @JsonProperty
            JsonHex.Bytes encodedCall
    ) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record NotoTransferMetadata(
            @JsonProperty
            ApproveExtraParams approvalParams,
            @JsonProperty
            NotoPublicTransaction transferWithApproval
    ) {
    }

    static final JsonABI.Entry mintABI = JsonABI.newFunction(
            "mint",
            JsonABI.newParameters(
                    JsonABI.newParameter("to", "string"),
                    JsonABI.newParameter("amount", "uint256")
            ),
            JsonABI.newParameters()
    );

    static final JsonABI.Entry transferABI = JsonABI.newFunction(
            "transfer",
            JsonABI.newParameters(
                    JsonABI.newParameter("to", "string"),
                    JsonABI.newParameter("amount", "uint256")
            ),
            JsonABI.newParameters()
    );

    static final JsonABI.Entry approveTransferABI = JsonABI.newFunction(
            "approveTransfer",
            JsonABI.newParameters(
                    JsonABI.newTupleArray("inputs", "FullState", JsonABI.newParameters(
                            JsonABI.newParameter("id", "bytes"),
                            JsonABI.newParameter("schema", "bytes32"),
                            JsonABI.newParameter("data", "bytes")
                    )),
                    JsonABI.newTupleArray("outputs", "FullState", JsonABI.newParameters(
                            JsonABI.newParameter("id", "bytes"),
                            JsonABI.newParameter("schema", "bytes32"),
                            JsonABI.newParameter("data", "bytes")
                    )),
                    JsonABI.newParameter("data", "bytes"),
                    JsonABI.newParameter("delegate", "address")
            ),
            JsonABI.newParameters()
    );

    public static NotoHelper deploy(String domainName, String from, Testbed testbed, ConstructorParams params) throws IOException {
        String address = testbed.getRpcClient().request("testbed_deploy", domainName, from, params);
        return new NotoHelper(domainName, testbed, address);
    }

    private NotoHelper(String domainName, Testbed testbed, String address) {
        this.domainName = domainName;
        this.testbed = testbed;
        this.address = address;
    }

    public String address() {
        return address;
    }

    private static Testbed.TransactionResult getTransactionInfo(LinkedHashMap<String, Object> res) {
        return new ObjectMapper().convertValue(res, Testbed.TransactionResult.class);
    }

    public List<NotoCoin> queryStates(JsonHex.Bytes32 schemaID, JsonQuery.Query query) throws IOException {
        List<HashMap<String, Object>> states = testbed.getRpcClient().request("pstate_queryContractStates",
                domainName, address, schemaID, query, "available");
        var mapper = new ObjectMapper();
        return states.stream().map(state -> mapper.convertValue(state, NotoCoin.class)).toList();
    }

    public void mint(String sender, String to, int amount) throws IOException {
        testbed.getRpcClient().request("testbed_invoke", new Testbed.TransactionInput(
                sender,
                JsonHex.addressFrom(address),
                mintABI,
                new HashMap<>() {{
                    put("to", to);
                    put("amount", amount);
                }}
        ), true);
    }

    public void transfer(String sender, String to, int amount) throws IOException {
        testbed.getRpcClient().request("testbed_invoke", new Testbed.TransactionInput(
                sender,
                JsonHex.addressFrom(address),
                transferABI,
                new HashMap<>() {{
                    put("to", to);
                    put("amount", amount);
                }}
        ), true);
    }

    public Testbed.TransactionResult prepareTransfer(String sender, String to, int amount) throws IOException {
        return getTransactionInfo(
                testbed.getRpcClient().request("testbed_prepare", new Testbed.TransactionInput(
                        sender,
                        JsonHex.addressFrom(address),
                        transferABI,
                        new HashMap<>() {{
                            put("to", to);
                            put("amount", amount);
                        }}
                )));
    }

    public void approveTransfer(String sender, List<Testbed.StateWithData> inputs, List<Testbed.StateWithData> outputs, JsonHex.Bytes data, String delegate) throws IOException {
        testbed.getRpcClient().request("testbed_invoke", new Testbed.TransactionInput(
                sender,
                JsonHex.addressFrom(address),
                approveTransferABI,
                new HashMap<>() {{
                    put("inputs", inputs);
                    put("outputs", outputs);
                    put("data", data);
                    put("delegate", delegate);
                }}
        ), true);
    }
}
