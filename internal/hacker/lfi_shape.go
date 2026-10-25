package hacker

import (
	"context"
	"regexp"
	"strings"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

var (
	// /etc/passwd records: root:x:0:0: / root:*:0:0: (the file content may
	// be embedded mid-line by the reading page — anchors stay off; the
	// BASELINE gate is the false-positive control, not line positions)
	rxUnixRoot = regexp.MustCompile(`root:[x*!]:0:0:`)
	// /etc/shadow hash records: root:$6$… / root:$y$…
	rxShadowHash = regexp.MustCompile(`root:\$[0-9a-z]\$`)
	// win.ini section headers
	rxWinIni = regexp.MustCompile(`(?i)\[(fonts|extensions|mail|shadow|mci extensions)\]`)
	// proc/self/environ K=V dumps
	rxEnviron = regexp.MustCompile(`(?i)DOCUMENT_ROOT=/|PATH=/usr/(local/)?bin`)
	// kernel banner
	rxKernelBanner = regexp.MustCompile(`(?i)Linux version`)
	// hosts records
	rxHostsRecord = regexp.MustCompile(`127\.0\.0\.[1-9][^0-9]|::1\s`)
)

// lfiShapeHit returns the FIRST structural record present in body but
// absent from the baseline; "" means no proof so far.
func lfiShapeHit(body, baseline string) string {
	for _, rx := range []*regexp.Regexp{rxUnixRoot, rxShadowHash, rxWinIni, rxEnviron, rxKernelBanner, rxHostsRecord} {
		hit := rx.FindString(body)
		if hit == "" {
			continue
		}
		if lfiHitInBaseline(hit, baseline) {
			continue // the page itself carries such records without a read
		}
		return strings.TrimSpace(hit)
	}
	return ""
}

// lfiHitInBaseline: a page that legitimately quotes `root:x:0:0:` in its
// own text must not lend those records to a payload echo either.
func lfiHitInBaseline(hit, baseline string) bool {
	if baseline == "" {
		return false
	}
	return strings.Contains(strings.ToLower(baseline), strings.ToLower(strings.TrimSpace(hit)))
}

// lfiBaseline caches the neutral round for this action instance (the
// target sweep repeats a dozen GETs against the same endpoint: fetching
// per attempt would triple the traffic for no information).
func (a *LFIReadAction) lfiBaseline(ctx context.Context, client *transport.Client) string {
	a.baselineOnce.Do(func() {
		base := a.vulnURL
		if idx := strings.Index(base, "?"); idx >= 0 {
			base = base[:idx]
		}
		req, err := client.Do(ctx, &types.Request{
			Method: "GET",
			URL:    base + "?" + a.param + "=",
		})
		if err == nil && req != nil {
			a.baselineBody = string(req.Body)
		}
	})
	return a.baselineBody
}
