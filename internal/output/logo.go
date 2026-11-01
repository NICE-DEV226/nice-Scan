package output

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Version is stamped by the CLI entry point (ldflags version); the
// renderers stay free of the build-time wiring.
var Version = "dev"

// RenderLogoCompact returns the sober wordmark block: bold name, version
// and tagline — no ASCII art.
func RenderLogoCompact() string {
	name := lipgloss.NewStyle().Foreground(Ink).Bold(true).Render("nice-scan")
	ver := FaintStyle.Render("v" + strings.TrimPrefix(Version, "v"))
	tag := MutedStyle.Render("Modern security reconnaissance — authorized use only")
	return "  " + name + "  " + ver + "\n  " + tag
}

// RenderLogoOneLine returns the compact identity glyph for header rows.
func RenderLogoOneLine() string {
	return AccentStyle.Render("◆")
}

func SetTabTitle(title string) {
	fmt.Print("\x1b]0;" + title + " \x07")
}

func SetTab() {
	SetTabTitle("nice-scan")
}
