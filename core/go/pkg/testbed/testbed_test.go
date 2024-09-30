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

package testbed

import (
	"context"
	"os"
	"path"
	"testing"

	"github.com/kaleido-io/paladin/core/pkg/config"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

func writeTestConfig(t *testing.T) (configFile string) {
	ctx := context.Background()
	log.SetLevel("debug")

	var conf *config.PaladinConfig
	err := config.ReadAndParseYAMLFile(ctx, "../../test/config/sqlite.memory.config.yaml", &conf)
	require.NoError(t, err)
	// For running in this unit test the dirs are different to the sample config
	conf.DB.SQLite.MigrationsDir = "../../db/migrations/sqlite"
	conf.DB.Postgres.MigrationsDir = "../../db/migrations/postgres"
	configFile = path.Join(t.TempDir(), "test.config.yaml")
	f, err := os.Create(configFile)
	require.NoError(t, err)
	defer f.Close()
	b, err := yaml.Marshal(conf)
	require.NoError(t, err)
	_, err = f.Write(b)
	require.NoError(t, err)

	return configFile
}

func TestYAMLConfigWorks(t *testing.T) {
	yamlConf := `
db:
  type: sqlite
  sqlite:
    dsn:           ":memory:"
    autoMigrate:   true
    migrationsDir: any
    debugQueries:  true
signer:
  keyStore:
    type: static
    static:
      keys:
        seed:
          encoding: none
          inline: '17250abf7976eae3c964e9704063f1457a8e1b4c0c0bd8b21ec8db5b88743c10'
rpcServer:
  http:
    port: 1234
  ws:
    disabled: true
blockchain:
   http:
     url: http://localhost:8545
   ws:
     url: ws://localhost:8546
domains:
  pente:
    plugin:
      type: jar
      class: any
    config:
      address: any
log:
  level: debug	
`
	var conf config.PaladinConfig
	err := yaml.Unmarshal([]byte(yamlConf), &conf)
	require.NoError(t, err)

	assert.NotNil(t, conf.DomainManagerConfig.Domains["pente"].Config)
}
