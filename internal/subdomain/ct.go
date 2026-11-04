package subdomain

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// CTLogSource is the production CTSource: it reads hostnames from a public
// Certificate-Transparency log API (crt.sh by default). A name in a CT log is
// evidence that someone once issued a real certificate for it — an independent
// corroboration of the DNS side.
type CTLogSource struct {
	Client  *http.Client
	BaseURL string // default https://crt.sh/
}

// NewCTLogSource builds a CT source over the supplied HTTP client (the caller
// owns timeouts/proxy). client may be nil, in which case a bounded default is used.
func NewCTLogSource(client *http.Client) *CTLogSource {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &CTLogSource{Client: client, BaseURL: "https://crt.sh/"}
}

// ctMaxBody bounds how much of a (potentially large) CT JSON answer we read.
const ctMaxBody = 12 << 20 // 12 MiB

// Hosts implements CTSource. It queries every logged name for `sub.<domain>`-style
// hosts and returns the hostnames the log attests to.
func (c *CTLogSource) Hosts(ctx context.Context, domain string) ([]string, error) {
	base := c.BaseURL
	if base == "" {
		base = "https://crt.sh/"
	}
	// "%25" is an encoded '%': the wildcard selects every name ending in
	// ".domain", i.e. all subdomains (and the log's own wildcard entries).
	q := base + "?q=%25." + domain + "&output=json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, q, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "nice-Scan subdomain-recon")
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("subdomain: CT log returned status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, ctMaxBody))
	return parseCTHostnames(body), nil
}

// ctEntry mirrors only the field we need from a crt.sh JSON object. name_value
// can carry several hostnames (one per line) for a multi-SAN certificate.
type ctEntry struct {
	NameValue string `json:"name_value"`
}

// parseCTHostnames is pure: turn a CT log JSON body into a deduped, lowercased
// list of hostnames. Tests feed it a captured body so nothing touches network.
func parseCTHostnames(body []byte) []string {
	// crt.sh returns an array; a single object is also tolerated.
	var arr []ctEntry
	if err := json.Unmarshal(body, &arr); err != nil {
		var one ctEntry
		if err2 := json.Unmarshal(body, &one); err2 != nil {
			return nil
		}
		arr = []ctEntry{one}
	}
	seen := map[string]bool{}
	var out []string
	for _, e := range arr {
		for _, line := range strings.Split(e.NameValue, "\n") {
			h := normalizeHost(line)
			if h == "" || seen[h] {
				continue
			}
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}
