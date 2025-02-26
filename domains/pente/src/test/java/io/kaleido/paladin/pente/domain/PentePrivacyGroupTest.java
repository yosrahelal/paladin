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
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.protobuf.util.JsonFormat;
import io.kaleido.paladin.testbed.Testbed;
import io.kaleido.paladin.toolkit.*;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;
import org.skyscreamer.jsonassert.JSONCompareMode;

import java.io.IOException;
import java.io.StringReader;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

public class PentePrivacyGroupTest {

    @Test
    @SuppressWarnings("unchecked")
    void testInitPrivacyGroupDefaults() throws Exception {

        var pente = new PenteDomain("", "");

        var jsonProtoParser = JsonFormat.parser();
        var reqBuilder = InitPrivacyGroupRequest.newBuilder();
        var inputData = new StringReader("""
                        {
                            "properties_json": "{\\"name\\":\\"bob\\"}",
                            "properties_abi_json": "[{\\"type\\":\\"string\\", \\"name\\": \\"name\\", \\"indexed\\":true}]",
                            "members": ["me@node1","you@node2"]
                        }
                """);
        jsonProtoParser.merge(inputData, reqBuilder);

        // Run it
        var res = pente.initPrivacyGroup(reqBuilder.build()).get();

        // Check the resulting state
        var expected = new ObjectMapper().readValue("""
                {
                    "name":"bob",
                    "salt":"REPLACE",
                    "pente": {
                        "members":["me@node1","you@node2"],
                        "evmVersion":"shanghai",
                        "endorsementType":"group_scoped_identities",
                        "externalCallsEnabled":false
                    }
                 }
                """, new TypeReference<Map<Object, Object>>() {});
        var received = new ObjectMapper().readValue(res.getGenesisStateJson(), new TypeReference<Map<Object, Object>>() {});
        expected.put("salt", received.get("salt"));
        assertEquals(expected, received);

        // Check the resulting state ABI definitino
        expected = new ObjectMapper().readValue("""
                {
                    "name": "",
                    "type": "tuple",
                    "internalType": "struct PentePrivacyGroup",
                    "components": [
                        { "name": "salt", "type": "bytes32", "indexed": true },
                        {
                           "name": "pente",
                           "type": "tuple",
                           "internalType": "struct PentePrivacyGroupSettings",
                           "components": [
                               {"name":"evmVersion", "type":"string"},
                               {"name":"endorsementType", "type":"string"},
                               {"name":"externalCallsEnabled", "type":"boolean"}
                           ]
                        },
                        { "name": "name", "type": "string", "indexed": true }
                    ]
                }
                """, new TypeReference<Map<Object, Object>>() {});
        received = new ObjectMapper().readValue(res.getGenesisAbiStateSchemaJson(), new TypeReference<Map<Object, Object>>() {});
        assertEquals(expected, received);

        // Check the resulting transaction parameters
        expected = new ObjectMapper().readValue("""
                {
                    "group": {
                       "salt": "REPLACED",
                       "members": ["me@node1","you@node2"]
                    },
                    "evmVersion": "shanghai",
                    "endorsementType": "group_scoped_identities",
                    "externalCallsEnabled": false
                }
                """, new TypeReference<Map<Object, Object>>() {});
        received = new ObjectMapper().readValue(res.getTransaction().getParamsJson(), new TypeReference<Map<Object, Object>>() {});
        ((Map<Object,Object>)expected.get("group")).put("salt", ((Map<Object,Object>)received.get("group")).get("salt"));
        assertEquals(expected, received);
    }
}