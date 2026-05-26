package output

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

const logoArt = `
    _   ___ ___ _____   ___  _   _ 
   / \ |_ _/ ___|  ___| / _ \| \ | |
  / _ \ | |\___ \ |_   / /_ \|  \| |
 / ___ \| | ___) |  _| / ___ \| |\  |
/_/   \_\_|____/|_|   \/   \_\_| \_|
`

const logoSub = "  Fast. Precise. Intelligent."

func RenderLogo() string {
	title := lipgloss.NewStyle().
		Foreground(accentCyan).
		Bold(true).
		Render(logoArt)

	tagline := lipgloss.NewStyle().
		Foreground(textMuted).
		Render(logoSub)

	return lipgloss.JoinVertical(lipgloss.Left, title, tagline)
}

func RenderLogoCompact() string {
	line1 := "  _   ___ ___ _____   ___  _   _ "
	line2 := " / \\ |_ _/ ___|  ___| / _ \\| \\ | |"
	line3 := "/ _ \\ | |\\___ \\ |_  / /_ \\|  \\| |"
	line4 := "/ ___ \\| | ___) |  _| / ___ \\| |\\  |"
	line5 := "/_/   \\_\\_|____/|_|   \\/   \\_\\_| \\_|"

	cyan := lipgloss.NewStyle().Foreground(accentCyan).Bold(true)
	muted := lipgloss.NewStyle().Foreground(textMuted)

	lines := []string{
		cyan.Render(line1),
		cyan.Render(line2),
		cyan.Render(line3),
		cyan.Render(line4),
		cyan.Render(line5),
		"",
		muted.Render("  Fast. Precise. Intelligent."),
	}

	return strings.Join(lines, "\n")
}

func RenderLogoOneLine() string {
	return lipgloss.NewStyle().
		Foreground(accentCyan).
		Bold(true).
		Render("NICE_SCAN")
}

func TabTitle() string {
	return "\x1b]0;NICE_SCAN \x07"
}

func SetTabTitle(title string) {
	fmt.Print("\x1b]0;" + title + " \x07")
}
