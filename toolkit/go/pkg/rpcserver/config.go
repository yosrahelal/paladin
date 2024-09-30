// Copyright © 2024 Kaleido, Inc.
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

package rpcserver

import (
	"github.com/kaleido-io/paladin/toolkit/pkg/confutil"
	"github.com/kaleido-io/paladin/toolkit/pkg/httpserver"
)

const DefaultHTTPPort = 8645
const DefaultWebSocketPort = 8646

var WSDefaults = WSEndpointConfig{
	ReadBufferSize:  confutil.P("64KB"),
	WriteBufferSize: confutil.P("64KB"),
}

type HTTPEndpointConfig struct {
	Disabled          bool `json:"disabled,omitempty"`
	httpserver.Config `json:",inline" yaml:"inline"`
}

type WSEndpointConfig struct {
	Disabled          bool `json:"disabled,omitempty"`
	httpserver.Config `json:",inline" yaml:"inline"`
	ReadBufferSize    *string `json:"readBufferSize"`
	WriteBufferSize   *string `json:"writeBufferSize"`
}

type Config struct {
	HTTP HTTPEndpointConfig `json:"http,omitempty"`
	WS   WSEndpointConfig   `json:"ws,omitempty"`
}
