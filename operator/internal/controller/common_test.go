package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMapToStruct(t *testing.T) {

	type example struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	tests := []struct {
		name    string
		data    map[string][]byte
		result  interface{}
		want    interface{}
		wantErr bool
	}{
		{
			name: "Valid mapping to example",
			data: map[string][]byte{
				"username": []byte("testuser"),
				"password": []byte("testpass"),
			},
			result: &example{},
			want: &example{
				Username: "testuser",
				Password: "testpass",
			},
			wantErr: false,
		},
		{
			name: "Missing key in map",
			data: map[string][]byte{
				"username": []byte("testuser"),
			},
			result: &example{},
			want: &example{
				Username: "testuser",
				Password: "",
			},
			wantErr: false,
		},
		{
			name:    "Result is not a pointer",
			data:    map[string][]byte{},
			result:  example{},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "Result is nil pointer",
			data:    map[string][]byte{},
			result:  (*example)(nil),
			want:    nil,
			wantErr: true,
		},
		{
			name: "Unsupported field type",
			data: map[string][]byte{"unsupported": []byte("value")},
			result: &struct {
				UnsupportedField int `json:"unsupported"`
			}{},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mapToStruct(tt.data, tt.result)

			if tt.wantErr {
				assert.Error(t, err, "Expected an error but got none")
			} else {
				assert.NoError(t, err, "Did not expect an error but got one")
			}

			if !tt.wantErr {
				assert.Equal(t, tt.want, tt.result, "Result mismatch")
			}
		})
	}
}
