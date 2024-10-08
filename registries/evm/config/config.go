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

package config

import (
	"io"
	"os"

	"github.com/kaleido-io/paladin/kata/pkg/blockindexer"
	"github.com/kaleido-io/paladin/kata/pkg/ethclient"
	"github.com/kaleido-io/paladin/kata/pkg/persistence"
	"github.com/kaleido-io/paladin/kata/pkg/signer/api"
	"gopkg.in/yaml.v2"
)

const CONFIG_FILE_ENV_KEY = "CONFIG_FILE"

const CONFIG_FILE_DEFAULT_PATH = "./data/config.yaml"

var Values Config

type APIConfig struct {
	Port int `yaml:"port"`
}

type Contract struct {
	Address string `yaml:"address"`
}

type Config struct {
	API         APIConfig           `yaml:"api"`
	Contract    Contract            `yaml:"contract"`
	Persistence persistence.Config  `yaml:"persistence"`
	Eth         ethclient.Config    `yaml:"eth"`
	Indexer     blockindexer.Config `yaml:"indexer"`
	Keys        api.Config          `yaml:"keys"`
}

func (config *Config) Load() error {
	configFilePath := getEnv(CONFIG_FILE_ENV_KEY, CONFIG_FILE_DEFAULT_PATH)
	yamlFile, err := os.Open(configFilePath)
	if err != nil {
		return err
	}

	defer yamlFile.Close()

	bytes, err := io.ReadAll(yamlFile)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(bytes, &config)
	if err != nil {
		return err
	}

	return nil
}

func (config *Config) Persist() error {
	content, err := yaml.Marshal(config)
	if err != nil {
		return err
	}

	configFilePath := getEnv(CONFIG_FILE_ENV_KEY, CONFIG_FILE_DEFAULT_PATH)
	err = os.WriteFile(configFilePath, content, 0644)
	if err != nil {
		return err
	}

	return nil
}

func getEnv(key, fallback string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		value = fallback
	}
	return value
}
