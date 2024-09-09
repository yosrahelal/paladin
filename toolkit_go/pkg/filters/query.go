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
	"maps"
)

const (
	// LimitKey is the key for the limit field in the query
	limitKey = "limit"
	// SortKey is the key for the sort field in the query
	sortKey = "sort"
	// EqKey is the key for the eq field in the query
	eqKey = "eq"
	// NqKey is the key for the nq field in the query
	nqKey = "neq"
	// GtKey is the key for the gt field in the query
	gtKey = "gt"
	// LtKey is the key for the lt field in the query
	ltKey = "lt"
	// LeKey is the key for the less than or equal field in the query
	leKey = "lte"
	// GeKey is the key for the greater than or equal field in the query
	geKey = "gte"
	// InKey is the key for the in field in the query
	inKey = "in"
	// NinKey is the key for the not in field in the query
	ninKey = "nin"
	// IsNullKey is the key for the is null field in the query
	isNullKey = "null"
	// LikeKey is the key for the like field in the query
	likeKey = "like"
	// CaseInsensitiveKey is the key for the case insensitive flag in the query
	caseInsensitiveKey = "caseInsensitive"
)

type addOns func() (string, bool)

var (
	// AddOns is a map of add-ons to be used in the query
	Not             addOns = func() (string, bool) { return "not", true }
	CaseInsensitive addOns = func() (string, bool) { return caseInsensitiveKey, true }
	CaseSensitive   addOns = func() (string, bool) { return caseInsensitiveKey, false }
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
	Sort(fields string) QueryBuilder

	// IsEqual adds an equal filter to the query
	IsEqual(field, value string, adds ...addOns) QueryBuilder

	// IsNotEqual adds a not equal filter to the query
	IsNotEqual(field, value string, adds ...addOns) QueryBuilder

	// IsGreaterThan adds a greater than filter to the query
	IsGreaterThan(field string, value int64) QueryBuilder

	// IsGreaterThanOrEqual adds a greater than or equal filter to the query
	IsGreaterThanOrEqual(field string, value int64) QueryBuilder

	// IsLessThan adds a less than filter to the query
	IsLessThan(field string, value int64) QueryBuilder

	// IsLessThanOrEqual adds a less than or equal filter to the query
	IsLessThanOrEqual(field string, value int64) QueryBuilder

	// IsIn adds an in filter to the query
	IsIn(field string, values []string, adds ...addOns) QueryBuilder

	// IsNotIn adds a not in filter to the query
	IsNotIn(field string, values []string, adds ...addOns) QueryBuilder

	// IsNull adds an is null filter to the query
	IsNull(field string) QueryBuilder

	// IsNotNull adds an is not null filter to the query
	IsNotNull(field string) QueryBuilder

	// IsLike adds a like filter to the query
	IsLike(field, value string) QueryBuilder

	// IsNotLike adds a not like filter to the query
	IsNotLike(field, value string) QueryBuilder

	// Or creates an OR condition between multiple queries
	Or(...QueryBuilder) QueryBuilder

	// Query returns the query
	Query() Query
}

// Ensure queryBuilderImpl implements QueryBuilder
var _ QueryBuilder = &queryBuilderImpl{}

type queryBuilderImpl struct {
	query *queryImpl
}

func NewQueryBuilder() *queryBuilderImpl {
	return &queryBuilderImpl{
		query: newQuery(),
	}
}

// Limit sets the limit of the query
func (qb *queryBuilderImpl) Limit(limit uint64) QueryBuilder {
	qb.query.set(limitKey, limit)
	return qb
}

// Sort adds a sort filter to the query
func (qb *queryBuilderImpl) Sort(fields string) QueryBuilder {
	qb.query.setSliceString(sortKey, []string{fields})
	return qb
}

// IsEqual adds an equal filter to the query
func (qb *queryBuilderImpl) IsEqual(field, value string, adds ...addOns) QueryBuilder {
	return qb.setField(eqKey, field, value, adds...)
}

// IsNotEqual adds a not equal filter to the query
func (qb *queryBuilderImpl) IsNotEqual(field, value string, adds ...addOns) QueryBuilder {
	return qb.setField(nqKey, field, value, adds...)
}

// IsGreaterThan adds a greater than filter to the query
func (qb *queryBuilderImpl) IsGreaterThan(field string, value int64) QueryBuilder {
	return qb.setField(gtKey, field, value)
}

// IsGreaterThanOrEqual adds a greater than or equal filter to the query
func (qb *queryBuilderImpl) IsGreaterThanOrEqual(field string, value int64) QueryBuilder {
	return qb.setField(geKey, field, value)
}

// IsLessThan adds a less than filter to the query
func (qb *queryBuilderImpl) IsLessThan(field string, value int64) QueryBuilder {
	return qb.setField(ltKey, field, value)
}

// IsLessThanOrEqual adds a less than or equal filter to the query
func (qb *queryBuilderImpl) IsLessThanOrEqual(field string, value int64) QueryBuilder {
	return qb.setField(leKey, field, value)
}

// IsIn adds an in filter to the query
func (qb *queryBuilderImpl) IsIn(field string, values []string, adds ...addOns) QueryBuilder {
	return qb.setFields(inKey, field, values, adds...)
}

// IsNotIn adds a not in filter to the query
func (qb *queryBuilderImpl) IsNotIn(field string, values []string, adds ...addOns) QueryBuilder {
	return qb.setFields(ninKey, field, values, adds...)
}

// IsNull adds an is null filter to the query
func (qb *queryBuilderImpl) IsNull(field string) QueryBuilder {
	return qb.setField(isNullKey, field, nil)
}

// IsNotNull adds an is not null filter to the query
func (qb *queryBuilderImpl) IsNotNull(field string) QueryBuilder {
	return qb.setField(isNullKey, field, nil, Not)
}

// IsLike adds a like filter to the query
func (qb *queryBuilderImpl) IsLike(field, value string) QueryBuilder {
	return qb.setField(likeKey, field, value)
}

// IsNotLike adds a not like filter to the query
func (qb *queryBuilderImpl) IsNotLike(field, value string) QueryBuilder {
	return qb.setField(likeKey, field, value, Not)
}

// Or creates an OR condition between multiple queries
func (qb *queryBuilderImpl) Or(q ...QueryBuilder) QueryBuilder {
	queries := make(map[string]interface{}, 0)
	for _, query := range q {
		maps.Copy(queries, query.Query().(*queryImpl).query)
	}
	qb.query.setSliceMap("or", []map[string]interface{}{queries})
	return qb
}

// Query returns the query
func (qb *queryBuilderImpl) Query() Query {
	return qb.query
}

func (qb *queryBuilderImpl) setField(key, field string, value interface{}, other ...addOns) QueryBuilder {
	m := map[string]interface{}{"field": field}
	if value != nil {
		m["value"] = value
	}
	if len(other) > 0 {
		for _, f := range other {
			k, v := f()
			m[k] = v
		}
	}

	qb.query.setSliceMap(key, []map[string]interface{}{m})
	return qb
}
func (qb *queryBuilderImpl) setFields(key, field string, value interface{}, other ...addOns) QueryBuilder {
	m := map[string]interface{}{"field": field}
	if value != nil {
		m["values"] = value
	}
	if len(other) > 0 {
		for _, f := range other {
			k, v := f()
			m[k] = v
		}
	}

	qb.query.setSliceMap(key, []map[string]interface{}{m})
	return qb
}

type queryImpl struct {
	query map[string]interface{}
}

func newQuery() *queryImpl {

	return &queryImpl{
		query: make(map[string]interface{}),
	}
}

// JSON returns the JSON representation of the query
func (q *queryImpl) JSON() ([]byte, error) {
	return json.Marshal(q.query)
}

// String returns the string representation of the query
func (q *queryImpl) String() string {
	j, _ := q.JSON()
	return string(j)
}

// set generic setter for query
func (q *queryImpl) set(key string, value interface{}) {
	q.query[key] = value
}

// setMap sets a map in the query
func (q *queryImpl) setMap(key string, value map[string]interface{}) {
	if existingValue, exists := q.query[key]; exists {
		if existingMap, ok := existingValue.(map[string]interface{}); ok {
			for k, v := range value {
				existingMap[k] = v
			}
			return
		}
	}
	q.query[key] = value
}

// setSlice sets a slice in the query
func (q *queryImpl) setSliceMap(key string, value []map[string]interface{}) {
	if existingValue, exists := q.query[key]; exists {
		if existingSliceMap, ok := existingValue.([]map[string]interface{}); ok {
			q.query[key] = append(existingSliceMap, value...)
			return
		}
	}
	q.query[key] = value
}

// setSlice sets a slice in the query
func (q *queryImpl) setSliceString(key string, value []string) {
	if existingValue, exists := q.query[key]; exists {
		if existingSlice, ok := existingValue.([]string); ok {
			q.query[key] = append(existingSlice, value...)
			return
		}
	}
	q.query[key] = value
}

// setSliceMapString sets a slice of maps with string keys and values in the query
func (q *queryImpl) setSliceMapString(key string, value []map[string]string) {
	if existingValue, exists := q.query[key]; exists {
		if existingSliceMap, ok := existingValue.([]map[string]string); ok {
			q.query[key] = append(existingSliceMap, value...)
			return
		}
	}
	q.query[key] = value
}
