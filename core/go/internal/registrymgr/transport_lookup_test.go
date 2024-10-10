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

package registrymgr

// func TestGetNodeTransportsCache(t *testing.T) {
// 	ctx, rm, _, m, done := newTestRegistry(t, false)
// 	defer done()

// 	m.db.ExpectQuery("SELECT.*registry_entries").WillReturnRows(sqlmock.NewRows([]string{
// 		"node", "registry", "transport", "details",
// 	}).AddRow(
// 		"node1", "test1", "websockets", "things and stuff",
// 	))

// 	expected := []*components.RegistryNodeTransportEntry{
// 		{
// 			Node:      "node1",
// 			Registry:  "test1",
// 			Transport: "websockets",
// 			Details:   "things and stuff",
// 		},
// 	}

// 	transports, err := rm.GetNodeTransports(ctx, "node1")
// 	require.NoError(t, err)
// 	assert.Equal(t, expected, transports)

// 	// Re-do from cache
// 	transports, err = rm.GetNodeTransports(ctx, "node1")
// 	require.NoError(t, err)
// 	assert.Equal(t, expected, transports)

// }

// func TestGetNodeTransportsErr(t *testing.T) {
// 	ctx, rm, _, m, done := newTestRegistry(t, false)
// 	defer done()

// 	m.db.ExpectQuery("SELECT.*registry_entries").WillReturnError(fmt.Errorf("pop"))

// 	_, err := rm.GetNodeTransports(ctx, "node1")
// 	require.Regexp(t, "pop", err)
// }
