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

package signerapi

import (
	"github.com/kaleido-io/paladin/core/pkg/proto"
	"github.com/kaleido-io/paladin/toolkit/pkg/confutil"
)

// To enable extending of the default configuration that Paladin uses when embedding this module,
// with additional configuration that is specific to particular environments
type ExtensibleConfig interface {
	KeyStoreConfig() *KeyStoreConfig
	KeyDerivationConfig() *KeyDerivationConfig
}

const (
	KeyStoreTypeFilesystem = "filesystem" // keystorev3 based filesystem storage
	KeyStoreTypeStatic     = "static"     // unencrypted keys in-line in the config
)

// Config can be directly embedded to provide ExtensibleConfig implementation
// (as in Paladin's core configuration) or you can create your own structure
// with more options as long as you provide a way to get hold of the base
// KeyStoreConfig / KeyDerivationConfig that the core module requires
// (by embedding those somewhere in your config hierarchy).
type Config struct {
	KeyStore      KeyStoreConfig      `json:"keyStore"`
	KeyDerivation KeyDerivationConfig `json:"keyDerivation"`
}

func (c *Config) KeyStoreConfig() *KeyStoreConfig {
	return &c.KeyStore
}

func (c *Config) KeyDerivationConfig() *KeyDerivationConfig {
	return &c.KeyDerivation
}

type KeyStoreConfig struct {
	Type              string                 `json:"type"`
	DisableKeyListing bool                   `json:"disableKeyListing"`
	KeyStoreSigning   bool                   `json:"keyStoreSigning"` // if HD Wallet or ZKP based signing is required, in-memory keys are required (so this needs to be false)
	FileSystem        FileSystemConfig       `json:"filesystem"`
	Static            StaticKeyStorageConfig `json:"static"`
}

type KeyDerivationType string

const (
	// Direct uses a unique piece of key material in the storage for each key, for this signing module
	KeyDerivationTypeDirect KeyDerivationType = "direct"
	// Hierarchical uses a single BIP39 seed mnemonic in the storage, combined with a BIP32 wallet to derive keys
	KeyDerivationTypeBIP32 KeyDerivationType = "bip32"
)

type ConfigKeyPathEntry struct {
	Name  string `json:"name"`
	Index uint64 `json:"index"`
}

type ConfigKeyEntry struct {
	Name       string               `json:"name"`
	Index      uint64               `json:"index"`
	Attributes map[string]string    `json:"attributes"`
	Path       []ConfigKeyPathEntry `json:"path"`
}

type KeyDerivationConfig struct {
	Type                  KeyDerivationType `json:"type"`
	SeedKeyPath           ConfigKeyEntry    `json:"seedKey"`
	BIP44DirectResolution bool              `json:"bip44DirectResolution"`
	BIP44Prefix           *string           `json:"bip44Prefix"`
	BIP44HardenedSegments *int              `json:"bip44HardenedSegments"`
}

var KeyDerivationDefaults = &KeyDerivationConfig{
	BIP44Prefix:           confutil.P("m/44'/60'"),
	BIP44HardenedSegments: confutil.P(1), // in addition to the prefix, so `m/44'/60'/0'/0/0` for example with 3 segments, on top of the prefix
	SeedKeyPath:           ConfigKeyEntry{Name: "seed", Index: 0},
}

func (k *ConfigKeyEntry) ToKeyResolutionRequest() *proto.ResolveKeyRequest {
	keyReq := &proto.ResolveKeyRequest{
		Name:       k.Name,
		Index:      k.Index,
		Attributes: k.Attributes,
		Path:       []*proto.ResolveKeyPathSegment{},
	}
	for _, p := range k.Path {
		keyReq.Path = append(keyReq.Path, &proto.ResolveKeyPathSegment{
			Name:  p.Name,
			Index: p.Index,
		})
	}
	return keyReq
}

type StaticKeyEntryEncoding string

const (
	StaticKeyEntryEncodingNONE   StaticKeyEntryEncoding = "none"
	StaticKeyEntryEncodingHEX    StaticKeyEntryEncoding = "hex"
	StaticKeyEntryEncodingBase64 StaticKeyEntryEncoding = "base64"
)

type StaticKeyEntryConfig struct {
	Encoding StaticKeyEntryEncoding `json:"encoding"`
	Filename string                 `json:"filename"`
	Trim     bool                   `json:"trim"`
	Inline   string                 `json:"inline"`
}

type StaticKeyStorageConfig struct {
	File string                          `json:"file,omitempty"` // whole file to use as a store
	Keys map[string]StaticKeyEntryConfig `json:"keys"`           // individual key entries in the config
}
