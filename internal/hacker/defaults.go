package hacker

import (
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// DefaultActions is the roster a hack run starts from. It contains the
// modules the command has always registered; destructive entries stay in the
// list so the report can name them as withheld, and the brain's dispatch gate
// refuses them without consent. The shell-upload / injection modules are not
// here: a caller registers those explicitly.
func DefaultActions(cfg *types.Config) []Action {
	proxy := ""
	if cfg != nil {
		proxy = cfg.Proxy
	}
	return []Action{
		&PassiveReconAction{Proxy: proxy},
		&CrawlAction{},
		&FuzzAction{},
		&SmartHeadersAction{},
		&TLSInspectorAction{},
		&FormIntegrityAction{},
		&PortScanAction{},
		&LoginBruteAction{},
		&JSSecretsAction{},
		&SourceMapAction{},
		&XSSAction{},
		&SQLiAction{},
		&JWTForgeAction{},
		&LFIAction{},
	}
}
