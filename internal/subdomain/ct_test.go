package subdomain

import (
	"reflect"
	"sort"
	"testing"
)

func TestParseCTHostnames(t *testing.T) {
	cases := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "array multi-line",
			body: `[{"name_value":"a.example.com\nb.example.com"},{"name_value":"a.example.com"}]`,
			want: []string{"a.example.com", "b.example.com"},
		},
		{
			name: "single object",
			body: `{"name_value":"x.example.com"}`,
			want: []string{"x.example.com"},
		},
		{
			name: "case and whitespace",
			body: `[{"name_value":"  A.Example.COM  "}]`,
			want: []string{"a.example.com"},
		},
		{
			// A bare "*.example.com" line is not a concrete host: normalizeHost
			// cuts at the '*', leaving "". Real multi-SAN certs pair it with a
			// literal "example.com" line, which this next case exercises.
			name: "wildcard line dropped, literal kept",
			body: `[{"name_value":"*.example.com\nexample.com"}]`,
			want: []string{"example.com"},
		},
		{
			name: "empty array",
			body: `[]`,
			want: nil,
		},
		{
			name: "malformed",
			body: `not json at all`,
			want: nil,
		},
		{
			name: "empty body",
			body: ``,
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseCTHostnames([]byte(tc.body))
			sort.Strings(got)
			sort.Strings(tc.want)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseCTHostnames = %v, want %v", got, tc.want)
			}
		})
	}
}
