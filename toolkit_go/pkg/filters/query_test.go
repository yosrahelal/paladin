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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestQuery(t *testing.T) {
	expectedQuery := `{
        "limit": 10,
        "sort": ["field1","field2"],
        "eq": [
            { "field": "field1", "value": "value1" },
            { "field": "field12", "value": "value12", "not": true, "caseInsensitive": true }
        ],
        "neq": [
            { "field": "field2", "value": "value2" }
        ],
        "like": [
            { "field": "field3", "value": "some value" }
        ],
        "lt": [
            { "field": "field4", "value": 12345 }
        ],
        "lte": [
            { "field": "field5", "value": 23456 }
        ],
        "gt": [
            { "field": "field6", "value": 34567 }
        ],
        "gte": [
            { "field": "field7", "value": 45678 }
        ],
        "in": [
            { "field": "field8", "values": ["a","b","c"] }
        ],
        "nin": [
            { "field": "field9", "values": ["x","y","z"] }
        ],
        "null": [
            { "field": "field10", "not": true },
            { "field": "field11" }
        ]
    }`

	query := NewQueryBuilder().
		Limit(10).
		Sort("field1").Sort("field2").
		IsEqual("field1", "value1").
		IsNotEqual("field2", "value2").
		IsLike("field3", "some value").
		IsLessThan("field4", 12345).
		IsLessThanOrEqual("field5", 23456).
		IsGreaterThan("field6", 34567).
		IsGreaterThanOrEqual("field7", 45678).
		IsIn("field8", []string{"a", "b", "c"}).
		IsNotIn("field9", []string{"x", "y", "z"}).
		IsNotNull("field10").
		IsNull("field11").
		IsEqual("field12", "value12", Not, CaseInsensitive).
		Query()

	jsonQuery, err := query.JSON()
	assert.NoError(t, err)
	assert.JSONEq(t, expectedQuery, string(jsonQuery))

	stringQuery := query.String()
	assert.JSONEq(t, expectedQuery, stringQuery)
}

func TestQuery_StringOr(t *testing.T) {
	expectedQuery := `{
        "or": [
            {
                "eq": [
                    { "field": "field1", "value": "value1" }
                ],
                "neq": [
                    { "field": "field2", "value": "value2" }
                ]
            },
            {
                "eq": [
                    { "field": "field3", "value": "value3" }
                ],
                "neq": [
                    { "field": "field4", "value": "value4" }
                ]
            }
        ]
    }`

	query := NewQueryBuilder().
		Or(
			NewQueryBuilder().IsEqual("field1", "value1"),
			NewQueryBuilder().IsNotEqual("field2", "value2"),
		).
		Or(
			NewQueryBuilder().IsEqual("field3", "value3"),
			NewQueryBuilder().IsNotEqual("field4", "value4"),
		).
		Query().String()

	assert.JSONEq(t, expectedQuery, query)
}

func TestQueryBuilderImpl_Limit(t *testing.T) {
	tests := []struct {
		name     string
		limit    uint64
		expected map[string]interface{}
	}{
		{
			name:  "Set positive limit",
			limit: 10,
			expected: map[string]interface{}{
				limitKey: uint64(10),
			},
		},
		{
			name:  "Set zero limit",
			limit: 0,
			expected: map[string]interface{}{
				limitKey: uint64(0),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			qb := NewQueryBuilder()
			qb.Limit(tt.limit)
			assert.Equal(t, tt.expected, qb.query.query)
		})
	}
}
func TestQueryBuilderImpl_Sort(t *testing.T) {
	tests := []struct {
		name     string
		fields   []string
		expected map[string]interface{}
	}{
		{
			name:   "Set single sort field",
			fields: []string{"field1"},
			expected: map[string]interface{}{
				sortKey: []string{"field1"},
			},
		},
		{
			name:   "Set multiple sort fields",
			fields: []string{"field1", "field2"},
			expected: map[string]interface{}{
				sortKey: []string{"field1", "field2"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			qb := NewQueryBuilder()
			for _, field := range tt.fields {
				qb.Sort(field)
			}
			assert.Equal(t, tt.expected, qb.query.query)
		})
	}
}

func TestQueryBuilderImpl_IsIn(t *testing.T) {
	tests := []struct {
		name     string
		field    string
		values   []string
		adds     []addOns
		expected map[string]interface{}
	}{
		{
			name:   "Set single in field",
			field:  "name",
			values: []string{"John", "Doe"},
			expected: map[string]interface{}{
				inKey: []map[string]interface{}{
					{"field": "name", "values": []string{"John", "Doe"}},
				},
			},
		},
		{
			name:   "Set in field with Not add-on",
			field:  "name",
			values: []string{"John", "Doe"},
			adds:   []addOns{Not},
			expected: map[string]interface{}{
				inKey: []map[string]interface{}{
					{"field": "name", "values": []string{"John", "Doe"}, "not": true},
				},
			},
		},
		{
			name:   "Set in field with CaseInsensitive add-on",
			field:  "name",
			values: []string{"John", "Doe"},
			adds:   []addOns{CaseInsensitive},
			expected: map[string]interface{}{
				inKey: []map[string]interface{}{
					{"field": "name", "values": []string{"John", "Doe"}, "caseInsensitive": true},
				},
			},
		},
		{
			name:   "Set in field with multiple add-ons",
			field:  "name",
			values: []string{"John", "Doe"},
			adds:   []addOns{Not, CaseInsensitive},
			expected: map[string]interface{}{
				inKey: []map[string]interface{}{
					{"field": "name", "values": []string{"John", "Doe"}, "not": true, "caseInsensitive": true},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			qb := NewQueryBuilder()
			qb.IsIn(tt.field, tt.values, tt.adds...)
			assert.Equal(t, tt.expected, qb.query.query)
		})
	}
}
func TestQueryBuilderImpl_IsNotIn(t *testing.T) {
	tests := []struct {
		name     string
		field    string
		values   []string
		adds     []addOns
		expected map[string]interface{}
	}{
		{
			name:   "Set single not in field",
			field:  "name",
			values: []string{"John", "Doe"},
			expected: map[string]interface{}{
				ninKey: []map[string]interface{}{
					{"field": "name", "values": []string{"John", "Doe"}},
				},
			},
		},
		{
			name:   "Set not in field with Not add-on",
			field:  "name",
			values: []string{"John", "Doe"},
			adds:   []addOns{Not},
			expected: map[string]interface{}{
				ninKey: []map[string]interface{}{
					{"field": "name", "values": []string{"John", "Doe"}, "not": true},
				},
			},
		},
		{
			name:   "Set not in field with CaseInsensitive add-on",
			field:  "name",
			values: []string{"John", "Doe"},
			adds:   []addOns{CaseInsensitive},
			expected: map[string]interface{}{
				ninKey: []map[string]interface{}{
					{"field": "name", "values": []string{"John", "Doe"}, "caseInsensitive": true},
				},
			},
		},
		{
			name:   "Set not in field with multiple add-ons",
			field:  "name",
			values: []string{"John", "Doe"},
			adds:   []addOns{Not, CaseInsensitive},
			expected: map[string]interface{}{
				ninKey: []map[string]interface{}{
					{"field": "name", "values": []string{"John", "Doe"}, "not": true, "caseInsensitive": true},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			qb := NewQueryBuilder()
			qb.IsNotIn(tt.field, tt.values, tt.adds...)

			assert.Equal(t, tt.expected, qb.query.query)
		})
	}
}
func TestQueryBuilderImpl_IsNull(t *testing.T) {
	tests := []struct {
		name     string
		field    string
		expected map[string]interface{}
	}{
		{
			name:  "Set single is null field",
			field: "name",
			expected: map[string]interface{}{
				isNullKey: []map[string]interface{}{
					{"field": "name"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			qb := NewQueryBuilder()
			qb.IsNull(tt.field)
			assert.Equal(t, tt.expected, qb.query.query)
		})
	}
}
func TestQueryBuilderImpl_IsLike(t *testing.T) {
	tests := []struct {
		name     string
		field    string
		value    string
		expected map[string]interface{}
	}{
		{
			name:  "Set single like field",
			field: "name",
			value: "John",
			expected: map[string]interface{}{
				likeKey: []map[string]interface{}{
					{"field": "name", "value": "John"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			qb := NewQueryBuilder()
			qb.IsLike(tt.field, tt.value)
			assert.Equal(t, tt.expected, qb.query.query)
		})
	}
}
func TestQueryBuilderImpl_IsNotLike(t *testing.T) {
	tests := []struct {
		name     string
		field    string
		value    string
		expected map[string]interface{}
	}{
		{
			name:  "Set single not like field",
			field: "name",
			value: "John",
			expected: map[string]interface{}{
				likeKey: []map[string]interface{}{
					{"field": "name", "value": "John", "not": true},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			qb := NewQueryBuilder()
			qb.IsNotLike(tt.field, tt.value)
			assert.Equal(t, tt.expected, qb.query.query)
		})
	}
}

func TestQueryBuilderImpl_setField(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		field    string
		value    interface{}
		adds     []addOns
		expected map[string]interface{}
	}{
		{
			name:  "Set single field",
			key:   eqKey,
			field: "name",
			value: "John",
			expected: map[string]interface{}{
				eqKey: []map[string]interface{}{
					{"field": "name", "value": "John"},
				},
			},
		},
		{
			name:  "Set field with Not add-on",
			key:   eqKey,
			field: "name",
			value: "John",
			adds:  []addOns{Not},
			expected: map[string]interface{}{
				eqKey: []map[string]interface{}{
					{"field": "name", "value": "John", "not": true},
				},
			},
		},
		{
			name:  "Set field with CaseInsensitive add-on",
			key:   eqKey,
			field: "name",
			value: "John",
			adds:  []addOns{CaseInsensitive},
			expected: map[string]interface{}{
				eqKey: []map[string]interface{}{
					{"field": "name", "value": "John", "caseInsensitive": true},
				},
			},
		},
		{
			name:  "Set field with multiple add-ons",
			key:   eqKey,
			field: "name",
			value: "John",
			adds:  []addOns{Not, CaseInsensitive},
			expected: map[string]interface{}{
				eqKey: []map[string]interface{}{
					{"field": "name", "value": "John", "not": true, "caseInsensitive": true},
				},
			},
		},
		{
			name:  "Set multiple fields",
			key:   eqKey,
			field: "name",
			value: "John",
			expected: map[string]interface{}{
				eqKey: []map[string]interface{}{
					{"field": "name", "value": "John"},
					{"field": "age", "value": "30"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			qb := NewQueryBuilder()
			qb.setField(tt.key, tt.field, tt.value, tt.adds...)
			if tt.name == "Set multiple fields" {
				qb.setField(tt.key, "age", "30")
			}
			assert.Equal(t, tt.expected, qb.query.query)
		})
	}
}
func TestQueryBuilderImpl_setFields(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		field    string
		values   []string
		adds     []addOns
		expected map[string]interface{}
	}{
		{
			name:   "Set single field with values",
			key:    inKey,
			field:  "name",
			values: []string{"John", "Doe"},
			expected: map[string]interface{}{
				inKey: []map[string]interface{}{
					{"field": "name", "values": []string{"John", "Doe"}},
				},
			},
		},
		{
			name:   "Set field with Not add-on",
			key:    inKey,
			field:  "name",
			values: []string{"John", "Doe"},
			adds:   []addOns{Not},
			expected: map[string]interface{}{
				inKey: []map[string]interface{}{
					{"field": "name", "values": []string{"John", "Doe"}, "not": true},
				},
			},
		},
		{
			name:   "Set field with CaseInsensitive add-on",
			key:    inKey,
			field:  "name",
			values: []string{"John", "Doe"},
			adds:   []addOns{CaseInsensitive},
			expected: map[string]interface{}{
				inKey: []map[string]interface{}{
					{"field": "name", "values": []string{"John", "Doe"}, "caseInsensitive": true},
				},
			},
		},
		{
			name:   "Set field with multiple add-ons",
			key:    inKey,
			field:  "name",
			values: []string{"John", "Doe"},
			adds:   []addOns{Not, CaseInsensitive},
			expected: map[string]interface{}{
				inKey: []map[string]interface{}{
					{"field": "name", "values": []string{"John", "Doe"}, "not": true, "caseInsensitive": true},
				},
			},
		},
		{
			name:   "Set multiple fields",
			key:    inKey,
			field:  "name",
			values: []string{"John", "Doe"},
			expected: map[string]interface{}{
				inKey: []map[string]interface{}{
					{"field": "name", "values": []string{"John", "Doe"}},
					{"field": "age", "values": []string{"30", "40"}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			qb := NewQueryBuilder()
			qb.setFields(tt.key, tt.field, tt.values, tt.adds...)
			if tt.name == "Set multiple fields" {
				qb.setFields(tt.key, "age", []string{"30", "40"})
			}
			assert.Equal(t, tt.expected, qb.query.query)
		})
	}
}
func TestSet(t *testing.T) {
	tests := []struct {
		name     string
		initial  map[string]interface{}
		key      string
		value    interface{}
		expected map[string]interface{}
	}{
		{
			name:     "Set value type string",
			initial:  map[string]interface{}{},
			key:      "key",
			value:    "value",
			expected: map[string]interface{}{"key": "value"},
		},
		{
			name:     "Set value type uint64",
			initial:  map[string]interface{}{},
			key:      "key",
			value:    uint64(98),
			expected: map[string]interface{}{"key": uint64(98)},
		},
		{
			name:     "Set value type int",
			initial:  map[string]interface{}{},
			key:      "key",
			value:    98,
			expected: map[string]interface{}{"key": 98},
		},
		{
			name:     "Set value type bool",
			initial:  map[string]interface{}{},
			key:      "key",
			value:    true,
			expected: map[string]interface{}{"key": true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := &queryImpl{query: tt.initial}
			q.set(tt.key, tt.value)
			assert.Equal(t, tt.expected, q.query)
		})
	}
}

func TestQueryImpl_setSliceMap(t *testing.T) {
	tests := []struct {
		name     string
		initial  map[string]interface{}
		key      string
		value    []map[string]string
		expected map[string]interface{}
	}{
		{
			name:    "Set single map",
			initial: map[string]interface{}{},
			key:     "key",
			value:   []map[string]string{{"field": "name", "value": "John"}},
			expected: map[string]interface{}{
				"key": []map[string]string{{"field": "name", "value": "John"}},
			},
		},
		{
			name:    "Set multiple maps",
			initial: map[string]interface{}{},
			key:     "key",
			value: []map[string]string{
				{"field": "name", "value": "John"},
				{"field": "age", "value": "30"},
			},
			expected: map[string]interface{}{
				"key": []map[string]string{
					{"field": "name", "value": "John"},
					{"field": "age", "value": "30"},
				},
			},
		},
		{
			name: "Append to existing maps",
			initial: map[string]interface{}{
				"key": []map[string]string{{"field": "name", "value": "John"}},
			},
			key: "key",
			value: []map[string]string{
				{"field": "age", "value": "30"},
			},
			expected: map[string]interface{}{
				"key": []map[string]string{
					{"field": "name", "value": "John"},
					{"field": "age", "value": "30"},
				},
			},
		},
		{
			name: "Overwrite non-slice map value",
			initial: map[string]interface{}{
				"key": "non-slice-map-value",
			},
			key: "key",
			value: []map[string]string{
				{"field": "name", "value": "John"},
			},
			expected: map[string]interface{}{
				"key": []map[string]string{
					{"field": "name", "value": "John"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := &queryImpl{query: tt.initial}
			q.setSliceMapString(tt.key, tt.value)
			assert.Equal(t, tt.expected, q.query)
		})
	}
}
func TestQueryImpl_setSlice(t *testing.T) {
	tests := []struct {
		name     string
		initial  map[string]interface{}
		key      string
		value    []string
		expected map[string]interface{}
	}{
		{
			name:    "Set single slice",
			initial: map[string]interface{}{},
			key:     "key",
			value:   []string{"value1"},
			expected: map[string]interface{}{
				"key": []string{"value1"},
			},
		},
		{
			name:    "Set multiple slices",
			initial: map[string]interface{}{},
			key:     "key",
			value:   []string{"value1", "value2"},
			expected: map[string]interface{}{
				"key": []string{"value1", "value2"},
			},
		},
		{
			name: "Append to existing slice",
			initial: map[string]interface{}{
				"key": []string{"value1"},
			},
			key:   "key",
			value: []string{"value2"},
			expected: map[string]interface{}{
				"key": []string{"value1", "value2"},
			},
		},
		{
			name: "Overwrite non-slice value",
			initial: map[string]interface{}{
				"key": "non-slice-value",
			},
			key:   "key",
			value: []string{"value1"},
			expected: map[string]interface{}{
				"key": []string{"value1"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := &queryImpl{query: tt.initial}
			q.setSliceString(tt.key, tt.value)
			assert.Equal(t, tt.expected, q.query)
		})
	}
}

func TestQueryImpl_setMap(t *testing.T) {
	tests := []struct {
		name     string
		initial  map[string]interface{}
		key      string
		value    map[string]interface{}
		expected map[string]interface{}
	}{
		{
			name:    "Set single map",
			initial: map[string]interface{}{},
			key:     "key",
			value:   map[string]interface{}{"field1": "value1"},
			expected: map[string]interface{}{
				"key": map[string]interface{}{"field1": "value1"},
			},
		},
		{
			name:    "Set multiple maps",
			initial: map[string]interface{}{},
			key:     "key",
			value: map[string]interface{}{
				"field1": "value1",
				"field2": "value2",
			},
			expected: map[string]interface{}{
				"key": map[string]interface{}{
					"field1": "value1",
					"field2": "value2",
				},
			},
		},
		{
			name: "Append to existing map",
			initial: map[string]interface{}{
				"key": map[string]interface{}{"field1": "value1"},
			},
			key: "key",
			value: map[string]interface{}{
				"field2": "value2",
			},
			expected: map[string]interface{}{
				"key": map[string]interface{}{
					"field1": "value1",
					"field2": "value2",
				},
			},
		},
		{
			name: "Overwrite non-map value",
			initial: map[string]interface{}{
				"key": "non-map-value",
			},
			key: "key",
			value: map[string]interface{}{
				"field1": "value1",
			},
			expected: map[string]interface{}{
				"key": map[string]interface{}{
					"field1": "value1",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := &queryImpl{query: tt.initial}
			q.setMap(tt.key, tt.value)
			assert.Equal(t, tt.expected, q.query)
		})
	}
}

func TestQueryImpl_JSON(t *testing.T) {
	q := &queryImpl{
		query: map[string]interface{}{
			"key1": "value1",
			"key2": "value2",
		},
	}
	expectedJSON := `{"key1":"value1","key2":"value2"}`
	jsonBytes, err := q.JSON()
	assert.NoError(t, err)
	assert.JSONEq(t, expectedJSON, string(jsonBytes))
}

func TestQueryImpl_String(t *testing.T) {
	q := &queryImpl{
		query: map[string]interface{}{
			"key1": "value1",
			"key2": "value2",
		},
	}
	expectedString := `{"key1":"value1","key2":"value2"}`
	assert.JSONEq(t, expectedString, q.String())
}
