package transport

import "github.com/NICE-DEV226/nice-Scan/internal/types"

// OptionsFromConfig maps operator configuration onto client options in one
// place. Every path that builds a client — the CLI's scan, audit, hack and
// shell commands, and the recon service a script or a model drives — has to
// honour the same timeout, retry, proxy, rate-limit and credential decisions.
// A mapping copied per caller is a mapping that drifts, and the drift is
// invisible until a scan silently ignores --rate-limit.
//
// Options the caller passes afterwards win: this returns the baseline, not the
// final word.
func OptionsFromConfig(cfg *types.Config) []ClientOption {
	if cfg == nil {
		cfg = types.DefaultConfig()
	}

	opts := []ClientOption{
		WithTimeout(cfg.Timeout),
		WithRetries(cfg.Retries),
		WithFollowRedirects(cfg.FollowRedirects),
		WithMaxRedirects(cfg.MaxRedirects),
		WithVerbose(cfg.Verbose),
	}
	if cfg.RateLimit > 0 {
		opts = append(opts, WithRateLimit(cfg.RateLimit))
	}
	if cfg.Proxy != "" {
		opts = append(opts, WithProxy(cfg.Proxy))
	}
	if cfg.Cookie != "" {
		opts = append(opts, WithCookie(cfg.Cookie))
	}
	if len(cfg.Headers) > 0 {
		opts = append(opts, WithHeaders(cfg.Headers))
	}
	return opts
}
