package auth

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		wantKey string
		wantErr error
	}{
		{
			name:    "missing Authorization header",
			headers: http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "wrong prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer abc123"},
			},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name: "missing token after ApiKey prefix",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantKey: "",
			// Split results in only 1 element → malformed
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name: "valid ApiKey header",
			headers: http.Header{
				"Authorization": []string{"ApiKey abc123"},
			},
			wantKey: "abbbababab", //"abc123",
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)

			// Error checks: we compare error messages because new errors can’t be directly equal.
			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tt.wantErr.Error())
				}
				if !strings.Contains(err.Error(), tt.wantErr.Error()) {
					t.Fatalf("expected error %q, got %q", tt.wantErr.Error(), err.Error())
				}
			} else if err != nil {
				t.Fatalf("expected no error, got %q", err.Error())
			}

			if gotKey != tt.wantKey {
				t.Fatalf("expected key %q, got %q", tt.wantKey, gotKey)
			}
		})
	}
}
