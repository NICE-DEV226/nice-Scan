package output

import "github.com/NICE-DEV226/nice-Scan/internal/types"

// Sanitize re-exports the terminal-safety filter for render sinks in this
// package. See internal/types.Sanitize.
func Sanitize(s string) string {
	return types.Sanitize(s)
}
