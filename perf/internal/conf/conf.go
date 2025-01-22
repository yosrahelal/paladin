// Copyright © 2025 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package conf

import (
	"time"

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/kaleido-io/paladin/config/pkg/pldconf"
)

type RunnerConfig struct {
	LogLevel                string
	Tests                   []TestCaseConfig
	Length                  time.Duration
	SigningKey              string
	ContractOptions         ContractOptions
	WSConfig                pldconf.WSClientConfig
	HTTPConfig              pldconf.HTTPClientConfig
	DelinquentAction        string
	Daemon                  bool
	LogEvents               bool
	MaxTimePerAction        time.Duration
	MaxActions              int64
	RampLength              time.Duration
	NoWaitSubmission        bool
	MaxSubmissionsPerSecond int
}

type PerformanceTestConfig struct {
	LogLevel   string                   `yaml:"logLevel" json:"logLevel"`
	Instances  []InstanceConfig         `json:"instances" yaml:"instances"`
	WSConfig   pldconf.WSClientConfig   `json:"wsConfig,omitempty" yaml:"wsConfig,omitempty"`
	HTTPConfig pldconf.HTTPClientConfig `json:"httpConfig,omitempty" yaml:"httpConfig,omitempty"`
	Daemon     bool                     `json:"daemon,omitempty" yaml:"daemon,omitempty"`
	Nodes      []NodeConfig             `yaml:"nodes" json:"nodes"`
	LogEvents  bool                     `json:"logEvents,omitempty" yaml:"logEvents,omitempty"`
}

type InstanceConfig struct {
	Name                    string           `yaml:"name" json:"name"`
	Tests                   []TestCaseConfig `yaml:"tests" json:"tests"`
	Length                  time.Duration    `yaml:"length" json:"length"`
	NodeIndex               int              `json:"nodeIndex" yaml:"nodeIndex"`
	SigningKey              string           `json:"signingKey,omitempty" yaml:"signingKey,omitempty"`
	ContractOptions         ContractOptions  `json:"contractOptions,omitempty" yaml:"contractOptions,omitempty"`
	MaxTimePerAction        time.Duration    `json:"maxTimePerAction,omitempty" yaml:"maxTimePerAction,omitempty"`
	MaxActions              int64            `json:"maxActions,omitempty" yaml:"maxActions,omitempty"`
	RampLength              time.Duration    `json:"rampLength,omitempty" yaml:"rampLength,omitempty"`
	NoWaitSubmission        bool             `json:"noWaitSubmission" yaml:"noWaitSubmission"`
	MaxSubmissionsPerSecond int              `json:"maxSubmissionsPerSecond" yaml:"maxSubmissionsPerSecond"`
	DelinquentAction        string           `json:"delinquentAction,omitempty" yaml:"delinquentAction,omitempty"`
}

type TestCaseConfig struct {
	Name           fftypes.FFEnum `json:"name" yaml:"name"`
	Workers        int            `json:"workers" yaml:"workers"`
	ActionsPerLoop int            `json:"actionsPerLoop" yaml:"actionsPerLoop"`
}

type NodeConfig struct {
	Name         string `json:"name" yaml:"name"`
	HTTPEndpoint string `json:"httpEndpoint" yaml:"httpEndpoint"`
	WSEndpoint   string `json:"wsEndpoint" yaml:"wsEndpoint"`
}

type ContractOptions struct {
	Address string `json:"address" yaml:"address"`
}

var (
	// PerfTestPublicContract invokes a public smart contract and checks for transaction receipts
	PerfTestPublicContract fftypes.FFEnum = "public_contract"
)

var (
	// DelinquentActionExit causes paladin perf to exit after detecting delinquent messages
	DelinquentActionExit fftypes.FFEnum = "exit"
	// DelinquentActionLog causes paladin perf to log and move on after delinquent messages
	DelinquentActionLog fftypes.FFEnum = "log"
)

var ValidPerfTests = map[string]fftypes.FFEnum{
	PerfTestPublicContract.String(): PerfTestPublicContract,
}
