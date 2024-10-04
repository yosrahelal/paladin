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

package pldconf

type DBConfig struct {
	Type     string         `json:"type"`
	Postgres PostgresConfig `json:"postgres"`
	SQLite   SQLiteConfig   `json:"sqlite"`
}

type PostgresConfig struct {
	SQLDBConfig `json:",inline"`
}

type SQLiteConfig struct {
	SQLDBConfig `json:",inline"`
}

// Extensible in case we want to add more options (not env vars are not available wrapped in Java)
type DSNParamLocation struct {
	File string `json:"file,omitempty"` // whole file contains the property value - will be trimmed before use
}

type SQLDBConfig struct {
	DSN             string                      `json:"dsn"` // can have {{.ParamName}} for replacement from params
	DSNParams       map[string]DSNParamLocation `json:"dsnParams"`
	MaxOpenConns    *int                        `json:"maxOpenConns"`
	MaxIdleConns    *int                        `json:"maxIdleConns"`
	ConnMaxIdleTime *string                     `json:"connMaxIdleTime"`
	ConnMaxLifetime *string                     `json:"connMaxLifetime"`
	AutoMigrate     *bool                       `json:"autoMigrate"`
	MigrationsDir   string                      `json:"migrationsDir"`
	DebugQueries    bool                        `json:"debugQueries"`
	StatementCache  *bool                       `json:"statementCache"`
}
