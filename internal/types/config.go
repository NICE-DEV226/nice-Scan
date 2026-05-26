package types

import "time"

func DefaultConfig() *Config {
	return &Config{
		Workers:   64,
		Timeout:   15 * time.Second,
		Retries:   2,
		RateLimit: 0,
		FollowRedirects: true,
		MaxRedirects:   5,
		OutputFormat: "terminal",
		HTTP2:      true,
	}
}
