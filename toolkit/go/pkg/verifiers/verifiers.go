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

package verifiers

// An ethereum address - 20 byte compressed public key identifier with 0x prefix (no checksum)
const ETH_ADDRESS = "eth_address"

// An ethereum address - 20 byte compressed public key identifier with 0x prefix and ERC-55 mixed-case checksum address encoding
const ETH_ADDRESS_CHECKSUM = "eth_address_checksum"

// ECDSA public key in standard form ([FIPS186] in uncompressed form [X9.62]) - hex encoded with no string prefix, and uncompressed prefix (0x04)

const HEX_ECDSA_UNCOMPRESSED_PUBKEY_NO_PREFIX = "hex_ecdsa_pubkey_no_prefix"

// ECDSA public key in standard form ([FIPS186] in uncompressed form [X9.62]) - hex encoded with 0x string prefix, and uncompressed prefix (0x04)
const HEX_ECDSA_UNCOMPRESSED_PUBKEY_0X_PREFIX = "hex_ecdsa_pubkey_0x_prefix"
