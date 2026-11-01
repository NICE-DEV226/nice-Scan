package hacker

import (
	"strings"
	"testing"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// The SevCritical "public S3 bucket" claim must rest on an executed anonymous
// object listing, not on a redirect or a non-error landing page.
func TestIsPublicBucketRequiresRealListing(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{"anonymous listing with objects", 200,
			`<ListBucketResult><Contents><Key>a.txt</Key></Contents></ListBucketResult>`, true},
		{"empty listing (no objects)", 200,
			`<ListBucketResult><Name>b</Name></ListBucketResult>`, false},
		{"access denied", 403, `<Error><Code>AccessDenied</Code></Error>`, false},
		{"region redirect body that lists nothing", 301, `<Error><Code>PermanentRedirect</Code></Error>`, false},
		{"plain landing page over 100 bytes", 200, strings.Repeat("<p>marketing copy</p>", 20), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := &types.Response{StatusCode: c.status, Body: []byte(c.body)}
			if got := isPublicBucket(resp); got != c.want {
				t.Errorf("isPublicBucket = %v, want %v", got, c.want)
			}
		})
	}
}
