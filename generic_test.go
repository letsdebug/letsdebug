package letsdebug

import (
	"reflect"
	"testing"
)

func TestParseCaaRecordProperties(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    CaaRecordProperties
		expectError bool
	}{
		{
			name:  "empty",
			input: "",
			expected: CaaRecordProperties{
				name:              "",
				accountUri:        "",
				validationMethods: nil,
			},
			expectError: false,
		},
		{
			name:  "name only",
			input: "example.com",
			expected: CaaRecordProperties{
				name:              "example.com",
				accountUri:        "",
				validationMethods: nil,
			},
			expectError: false,
		},
		{
			name:  "name and accountUri",
			input: "example.com;accounturi=https://example.com/account/123",
			expected: CaaRecordProperties{
				name:              "example.com",
				accountUri:        "https://example.com/account/123",
				validationMethods: nil,
			},
			expectError: false,
		},
		{
			name:  "name and validationMethods",
			input: "example.com;validationmethods=dns-01",
			expected: CaaRecordProperties{
				name:       "example.com",
				accountUri: "",
				validationMethods: []string{
					"dns-01",
				},
			},
			expectError: false,
		},
		{
			name:  "name and accountUri and validationMethods",
			input: " example.com ; accounturi = https://example.com/account/123 ; validationmethods = http-01,dns-01",
			expected: CaaRecordProperties{
				name:       "example.com",
				accountUri: "https://example.com/account/123",
				validationMethods: []string{
					"http-01",
					"dns-01",
				},
			},
			expectError: false,
		},
		{
			name:  "unknown fields",
			input: "example.com;accounturi=https://example.com/account/123;validationmethods=http-01,dns-01,newChallenge;extra=unexpected",
			expected: CaaRecordProperties{
				name:       "example.com",
				accountUri: "https://example.com/account/123",
				validationMethods: []string{
					"http-01",
					"dns-01",
					"newChallenge",
				},
			},
			expectError: false,
		},
		{
			name:  "invalid format",
			input: "example.com; invalidValue",
			expected: CaaRecordProperties{
				name:              "",
				accountUri:        "",
				validationMethods: nil,
			},
			expectError: true,
		},
		{
			name:  "empty record",
			input: ";",
			expected: CaaRecordProperties{
				name:              "",
				accountUri:        "",
				validationMethods: nil,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseCaaRecordProperties(tt.input)
			if tt.expectError && err == nil {
				t.Fatalf("expected error, got none")
			}
			if !tt.expectError && err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}

			if !reflect.DeepEqual(result, tt.expected) {
				t.Fatalf("expected: %+v, got: %+v", tt.expected, result)
			}
		})
	}
}
