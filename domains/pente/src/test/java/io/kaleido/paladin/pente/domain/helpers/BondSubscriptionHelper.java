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

import io.kaleido.paladin.toolkit.JsonABI;
import io.kaleido.paladin.toolkit.JsonHex;
import io.kaleido.paladin.toolkit.ResourceLoader;

import java.io.IOException;
import java.util.HashMap;

public class BondSubscriptionHelper {
    final PenteHelper pente;
    final JsonHex.Address address;

    static final JsonABI.Parameters constructorParams = JsonABI.newParameters(
            JsonABI.newParameter("distributionAddress", "address"),
            JsonABI.newParameter("units", "uint256")
    );

    public static BondSubscriptionHelper deploy(PenteHelper pente, String sender, Object inputs) throws IOException {
        String bytecode = ResourceLoader.jsonResourceEntryText(
                BondSubscriptionHelper.class.getClassLoader(),
                "contracts/private/BondSubscription.sol/BondSubscription.json",
                "bytecode"
        );

        var address = pente.deploy(sender, bytecode, constructorParams, inputs);
        return new BondSubscriptionHelper(pente, address);
    }

    private BondSubscriptionHelper(PenteHelper pente, JsonHex.Address address) {
        this.pente = pente;
        this.address = address;
    }

    public JsonHex.Address address() {
        return address;
    }

    public void markReceived(String sender, int units) throws IOException {
        pente.invoke(
                "markReceived",
                JsonABI.newParameters(
                        JsonABI.newParameter("units", "uint256")
                ),
                sender,
                address,
                new HashMap<>() {{
                    put("units", units);
                }}
        );
    }
}
