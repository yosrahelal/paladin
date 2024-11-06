package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Assuming adjustTemplatePlaceholders is defined in the same package

func TestAdjustTemplatePlaceholders(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Standard placeholder replacement",
			input:    "'{{`{{some content}}`}}'",
			expected: "\"{{some content}}\"",
		},
		{
			name:     "Nested placeholders",
			input:    "'{{`{{nested 'placeholders'}}`}}'",
			expected: "\"{{nested 'placeholders'}}\"",
		},
		{
			name:     "Multiple placeholders",
			input:    "'{{`{{first}}`}}' and '{{`{{second}}`}}'",
			expected: "\"{{first}}\" and \"{{second}}\"",
		},
		{
			name:     "No placeholders",
			input:    "No placeholders here",
			expected: "No placeholders here",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "Partial placeholder",
			input:    "'{{`{{incomplete",
			expected: "\"{{incomplete", // No change expected
		},
		{
			name:     "Already adjusted string",
			input:    "\"{{already adjusted}}\"",
			expected: "\"{{already adjusted}}\"",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := adjustTemplatePlaceholders(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}
