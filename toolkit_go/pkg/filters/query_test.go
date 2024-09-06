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

func TestQueryBuilder(t *testing.T) {

	expectedQuery := `{"eq":[{"field":"owner","value":"random_1"},{"field":"author","value":"random_2"}],"gt":[{"field":".timestamp","value":"1693456789"}],"limit":10,"sort":[".created",".timestamp"]}`

	query := NewQueryBuilder().
		Limit(10).
		Sort(".created").
		Sort(".timestamp").
		Eq("owner", "random_1").
		Eq("author", "random_2").
		Gt(".timestamp", "1693456789").
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
			name:   "Single sort field",
			fields: []string{".created"},
			expected: map[string]interface{}{
				sortKey: []string{".created"},
			},
		},
		{
			name:   "Multiple sort fields",
			fields: []string{".created", ".timestamp"},
			expected: map[string]interface{}{
				sortKey: []string{".created", ".timestamp"},
			},
		},
		{
			name:   "No sort fields",
			fields: []string{},
			expected: map[string]interface{}{
				sortKey: []string{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			qb := NewQueryBuilder()
			qb.Sort(tt.fields...)
			assert.Equal(t, tt.expected, qb.query.query)
		})
	}
}
func TestQueryBuilderImpl_Eq(t *testing.T) {
	tests := []struct {
		name     string
		set      []map[string]string
		expected string
	}{
		{
			name:     "Set single eq field",
			set:      []map[string]string{{"field": "name", "value": "John"}},
			expected: `{"eq":[{"field": "name", "value": "John"}]}`,
		},
		{
			name: "Set multiple eq fields",
			set: []map[string]string{
				{"field": "name", "value": "John"},
				{"field": "age", "value": "30"},
			},
			expected: `{"eq":[{"field": "name", "value": "John"}, {"field": "age", "value": "30"}]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var qb QueryBuilder
			qb = NewQueryBuilder()
			for _, s := range tt.set {
				qb = qb.Eq(s["field"], s["value"])
			}
			assert.JSONEq(t, tt.expected, qb.Query().String())
		})
	}
}
func TestQueryBuilderImpl_Nq(t *testing.T) {
	tests := []struct {
		name     string
		set      []map[string]string
		expected string
	}{
		{
			name:     "Set single nq field",
			set:      []map[string]string{{"field": "name", "value": "John"}},
			expected: `{"nq":[{"field": "name", "value": "John"}]}`,
		},
		{
			name: "Set multiple nq fields",
			set: []map[string]string{
				{"field": "name", "value": "John"},
				{"field": "age", "value": "30"},
			},
			expected: `{"nq":[{"field": "name", "value": "John"}, {"field": "age", "value": "30"}]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var qb QueryBuilder
			qb = NewQueryBuilder()
			for _, s := range tt.set {
				qb = qb.Nq(s["field"], s["value"])
			}
			assert.JSONEq(t, tt.expected, qb.Query().String())
		})
	}
}

func TestQueryBuilderImpl_Gt(t *testing.T) {
	tests := []struct {
		name     string
		set      []map[string]string
		expected string
	}{
		{
			name:     "Set single gt field",
			set:      []map[string]string{{"field": "name", "value": "John"}},
			expected: `{"gt":[{"field": "name", "value": "John"}]}`,
		},
		{
			name: "Set multiple gt fields",
			set: []map[string]string{
				{"field": "name", "value": "John"},
				{"field": "age", "value": "30"},
			},
			expected: `{"gt":[{"field": "name", "value": "John"}, {"field": "age", "value": "30"}]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var qb QueryBuilder
			qb = NewQueryBuilder()
			for _, s := range tt.set {
				qb = qb.Gt(s["field"], s["value"])
			}
			assert.JSONEq(t, tt.expected, qb.Query().String())
		})
	}
}
func TestQueryBuilderImpl_Lt(t *testing.T) {
	tests := []struct {
		name     string
		set      []map[string]string
		expected string
	}{
		{
			name:     "Set single lt field",
			set:      []map[string]string{{"field": "name", "value": "John"}},
			expected: `{"lt":[{"field": "name", "value": "John"}]}`,
		},
		{
			name: "Set multiple lt fields",
			set: []map[string]string{
				{"field": "name", "value": "John"},
				{"field": "age", "value": "30"},
			},
			expected: `{"lt":[{"field": "name", "value": "John"}, {"field": "age", "value": "30"}]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var qb QueryBuilder
			qb = NewQueryBuilder()
			for _, s := range tt.set {
				qb = qb.Lt(s["field"], s["value"])
			}
			assert.JSONEq(t, tt.expected, qb.Query().String())
		})
	}
}
func TestQueryBuilderImpl_setField(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		field    string
		value    string
		expected map[string]interface{}
	}{
		{
			name:  "Set eq field",
			key:   eqKey,
			field: "name",
			value: "John",
			expected: map[string]interface{}{
				eqKey: []map[string]string{{"field": "name", "value": "John"}},
			},
		},
		{
			name:  "Set nq field",
			key:   nqKey,
			field: "age",
			value: "30",
			expected: map[string]interface{}{
				nqKey: []map[string]string{{"field": "age", "value": "30"}},
			},
		},
		{
			name:  "Set gt field",
			key:   gtKey,
			field: "score",
			value: "100",
			expected: map[string]interface{}{
				gtKey: []map[string]string{{"field": "score", "value": "100"}},
			},
		},
		{
			name:  "Set lt field",
			key:   ltKey,
			field: "height",
			value: "180",
			expected: map[string]interface{}{
				ltKey: []map[string]string{{"field": "height", "value": "180"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			qb := NewQueryBuilder()
			qb.setField(tt.key, tt.field, tt.value)
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
