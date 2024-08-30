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

package filters

import (
	"encoding/json"
)

const (
	// LimitKey is the key for the limit field in the query
	limitKey = "limit"
	// SortKey is the key for the sort field in the query
	sortKey = "sort"
	// EqKey is the key for the eq field in the query
	eqKey = "eq"
	// NqKey is the key for the nq field in the query
	nqKey = "nq"
	// GtKey is the key for the gt field in the query
	gtKey = "gt"
	// LtKey is the key for the lt field in the query
	ltKey = "lt"
)

type Query interface {
	String() string
	JSON() ([]byte, error)
}

// QueryBuilder defines an interface for building queries
type QueryBuilder interface {
	// Limit sets the limit of the query
	Limit(limit uint64) QueryBuilder

	// Sort adds a sort filter to the query
	Sort(fields ...string) QueryBuilder

	// Eq adds an equal filter to the query
	Eq(key, value string) QueryBuilder

	// Nq adds a not equal filter to the query
	Nq(key, value string) QueryBuilder

	// Gt adds a greater than filter to the query
	Gt(key, value string) QueryBuilder

	// Lt adds a less than filter to the query
	Lt(key, value string) QueryBuilder

	// Query returns the query
	Query() Query
}

type QueryBuilderImpl struct {
	query *QueryImpl
}

func NewQueryBuilder() *QueryBuilderImpl {
	return &QueryBuilderImpl{
		query: newQuery(),
	}
}

// Limit sets the limit of the query
func (qb *QueryBuilderImpl) Limit(limit uint64) QueryBuilder {
	qb.query.set(limitKey, limit)
	return qb
}

// Sort adds a sort filter to the query
func (qb *QueryBuilderImpl) Sort(fields ...string) QueryBuilder {
	qb.query.set(sortKey, fields)
	return qb
}

// Eq adds an equal filter to the query
func (qb *QueryBuilderImpl) Eq(field, value string) QueryBuilder {
	return qb.setField(eqKey, field, value)
}

// Nq adds a not equal filter to the query
func (qb *QueryBuilderImpl) Nq(field, value string) QueryBuilder {
	return qb.setField(nqKey, field, value)
}

// Gt adds a greater than filter to the query
func (qb *QueryBuilderImpl) Gt(field, value string) QueryBuilder {
	return qb.setField(gtKey, field, value)
}

// Lt adds a less than filter to the query
func (qb *QueryBuilderImpl) Lt(field, value string) QueryBuilder {
	return qb.setField(ltKey, field, value)
}

func (qb *QueryBuilderImpl) Query() Query {
	return qb.query
}

func (qb *QueryBuilderImpl) setField(key, field, value string) QueryBuilder {
	qb.query.set(key, []map[string]string{{"field": field, "value": value}})
	return qb
}

type QueryImpl struct {
	query map[string]interface{}
}

func newQuery() *QueryImpl {

	return &QueryImpl{
		query: make(map[string]interface{}),
	}
}

// JSON returns the JSON representation of the query
func (q *QueryImpl) JSON() ([]byte, error) {
	return json.Marshal(q.query)
}

// String returns the string representation of the query
func (q *QueryImpl) String() string {
	j, _ := q.JSON()
	return string(j)
}

func (q *QueryImpl) set(key string, value interface{}) {
	if existingValue, exists := q.query[key]; exists {
		if existingMap, ok := existingValue.(map[string]interface{}); ok {
			if newMap, ok := value.(map[string]interface{}); ok {
				for k, v := range newMap {
					existingMap[k] = v
				}
				return
			}
		}
		if existingSlice, ok := existingValue.([]string); ok {
			if newSlice, ok := value.([]string); ok {
				existingSlice = append(existingSlice, newSlice...)
				q.query[key] = existingSlice
				return
			}
		}
		if existingSliceMap, ok := existingValue.([]map[string]string); ok {
			if newSliceMap, ok := value.([]map[string]string); ok {
				existingSliceMap = append(existingSliceMap, newSliceMap...)
				q.query[key] = existingSliceMap
				return
			}
		}

	}
	q.query[key] = value
}
