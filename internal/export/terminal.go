package export

import (
	"fmt"
	"os"
	"strings"

	"github.com/gorkemguler/zarf/internal/model"
)

type ansi struct {
	reset, bold, dim, red, yellow, green, cyan, magenta, gray string
}

func newANSI(useColor bool) ansi {
	if !useColor {
		return ansi{}
	}
	return ansi{
		reset:   "\033[0m",
		bold:    "\033[1m",
		dim:     "\033[2m",
		red:     "\033[31m",
		yellow:  "\033[33m",
		green:   "\033[32m",
		cyan:    "\033[36m",
		magenta: "\033[35m",
		gray:    "\033[90m",
	}
}

// ShouldUseColor honors NO_COLOR and non-TTY detection.
func ShouldUseColor(noColorFlag bool) bool {
	if noColorFlag || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// RenderTerminal formats a crisp, tinfoil-inspired terminal autopsy report.
func RenderTerminal(rep *model.Report, useColor bool) string {
	c := newANSI(useColor)
	var b strings.Builder

	fmt.Fprintf(&b, "%s  ███████╗ █████╗ ██████╗ ███████╗%s\n", c.cyan+c.bold, c.reset)
	fmt.Fprintf(&b, "%s  ╚══███╔╝██╔══██╗██╔══██╗██╔════╝%s  v%s  ·  100%% offline · 0 network calls\n", c.cyan+c.bold, c.reset, rep.ToolVersion)
	fmt.Fprintf(&b, "%s    ███╔╝ ███████║██████╔╝█████╗  %s\n", c.cyan+c.bold, c.reset)
	fmt.Fprintf(&b, "%s   ███╔╝  ██╔══██║██╔══██╗██╔══╝  %s  file   %s (%d bytes)\n", c.cyan+c.bold, c.reset, rep.Evidence.Filename, rep.Evidence.SizeBytes)
	fmt.Fprintf(&b, "%s  ███████╗██║  ██║██║  ██║██║     %s  sha256 %s\n\n", c.cyan+c.bold, c.reset, rep.Evidence.SHA256)

	// Score bar
	vColor := verdictColor(c, rep.Score.Verdict)
	filled := rep.Score.Total * 28 / 100
	if filled > 28 {
		filled = 28
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", 28-filled)
	fmt.Fprintf(&b, "  %sPHISHING RISK SCORE%s   %s%s%s   %s%s%s  %s%d/100%s\n",
		c.bold, c.reset, vColor+c.bold, rep.Score.Verdict, c.reset, vColor, bar, c.reset, c.bold, rep.Score.Total, c.reset)
	fmt.Fprintf(&b, "  %sCategories: headers=%d · auth=%d · hops=%d · body=%d · urls=%d · attachments=%d%s\n\n",
		c.gray,
		rep.Score.Categories["headers"], rep.Score.Categories["auth"], rep.Score.Categories["hops"],
		rep.Score.Categories["body"], rep.Score.Categories["urls"], rep.Score.Categories["attachments"], c.reset)

	// Envelope & Identity
	section(&b, c, "ENVELOPE & IDENTITY")
	if rep.Headers.From != nil {
		fmt.Fprintf(&b, "  From         %s <%s>\n", rep.Headers.From.DisplayName, rep.Headers.From.Address)
	}
	if rep.Headers.ReturnPath != nil {
		fmt.Fprintf(&b, "  Return-Path  %s\n", rep.Headers.ReturnPath.Address)
	}
	if len(rep.Headers.ReplyTo) > 0 {
		var rts []string
		for _, r := range rep.Headers.ReplyTo {
			rts = append(rts, r.Address)
		}
		fmt.Fprintf(&b, "  Reply-To     %s\n", strings.Join(rts, ", "))
	}
	fmt.Fprintf(&b, "  Subject      %s\n", rep.Headers.Subject)
	if rep.Headers.Date != "" {
		fmt.Fprintf(&b, "  Date         %s\n", rep.Headers.Date)
	}
	fmt.Fprintf(&b, "  Auth         %s\n", rep.Auth.Summary)
	for _, d := range rep.Auth.DKIMSignatures {
		status := c.green + "bh=MATCH" + c.reset
		if !d.BodyHashMatch {
			status = c.red + "bh=MISMATCH" + c.reset
		}
		fmt.Fprintf(&b, "  DKIM #%d      d=%s s=%s a=%s [%s]\n", d.Index, d.Domain, d.Selector, d.Algorithm, status)
	}
	b.WriteByte('\n')

	// Findings
	section(&b, c, fmt.Sprintf("FINDINGS (%d)", len(rep.Findings)))
	if len(rep.Findings) == 0 {
		fmt.Fprintf(&b, "  %s✓  CLEAN     No suspicious phishing indicators detected offline.%s\n", c.green, c.reset)
	} else {
		for _, f := range rep.Findings {
			sc := sevColor(c, f.Severity)
			fmt.Fprintf(&b, "  %s%-8s%s  %s%-8s%s  (+%2d)  %s%s%s\n",
				sc+c.bold, f.Severity, c.reset,
				c.gray, f.RuleID, c.reset,
				f.Points, c.bold, f.Title, c.reset)
			if f.Evidence != "" {
				fmt.Fprintf(&b, "  %s          │ %s%s\n", c.gray, f.Evidence, c.reset)
			}
		}
	}
	b.WriteByte('\n')

	// Hop Chain
	section(&b, c, fmt.Sprintf("SMTP HOP CHAIN (%d hops)", len(rep.Hops.Hops)))
	if len(rep.Hops.Hops) == 0 {
		fmt.Fprintf(&b, "  %s(no Received headers)%s\n", c.gray, c.reset)
	} else {
		for _, h := range rep.Hops.Hops {
			tlsBadge := c.yellow + "PLAIN" + c.reset
			if h.TLS {
				tlsBadge = c.green + "TLS  " + c.reset
			}
			delayStr := "origin"
			if h.DelaySeconds != nil {
				delayStr = fmt.Sprintf("%+.0fs", *h.DelaySeconds)
				if h.ClockSkew {
					delayStr = c.red + delayStr + " SKEW" + c.reset
				}
			}
			ipPart := ""
			if h.FromIP != "" {
				ipPart = fmt.Sprintf(" [%s/%s]", h.FromIP, h.IPScope)
			}
			fmt.Fprintf(&b, "  #%d  %s%s  ──▶  %s  (%s %s · %s)\n",
				h.Index, emptyDash(h.FromHost), ipPart, emptyDash(h.ByHost), emptyDash(h.Protocol), tlsBadge, delayStr)
		}
	}
	b.WriteByte('\n')

	// URLs
	if len(rep.URLs) > 0 {
		section(&b, c, fmt.Sprintf("EXTRACTED URLs (%d)", len(rep.URLs)))
		for _, u := range rep.URLs {
			sc := sevColor(c, u.Severity)
			fmt.Fprintf(&b, "  %s%-8s%s  [%3d]  %s  %s(%s)%s\n", sc+c.bold, u.Severity, c.reset, u.RiskScore, u.Defanged, c.gray, u.Source, c.reset)
			if u.IsPunycode {
				fmt.Fprintf(&b, "  %s          │ IDN decoded: %s%s\n", c.yellow, u.DecodedHost, c.reset)
			}
			for _, r := range u.Reasons {
				fmt.Fprintf(&b, "  %s          │ %s%s\n", c.gray, r, c.reset)
			}
		}
		b.WriteByte('\n')
	}

	// Attachments
	if len(rep.Attachments) > 0 {
		section(&b, c, fmt.Sprintf("ATTACHMENTS (%d)", len(rep.Attachments)))
		for _, a := range rep.Attachments {
			sc := sevColor(c, a.Severity)
			fmt.Fprintf(&b, "  %s%-8s%s  %s  (%d B · entropy=%.2f · magic=%s)\n",
				sc+c.bold, a.Severity, c.reset, a.Filename, a.SizeBytes, a.Entropy, a.DetectedMagic)
			fmt.Fprintf(&b, "  %s          │ sha256=%s%s\n", c.gray, a.SHA256, c.reset)
			for _, r := range a.Reasons {
				fmt.Fprintf(&b, "  %s          │ ! %s%s\n", c.yellow, r, c.reset)
			}
		}
		b.WriteByte('\n')
	}

	// Defanged IOCs
	section(&b, c, "DEFANGED IOCs")
	if len(rep.IOCs.DefangedIPs) > 0 {
		fmt.Fprintf(&b, "  IPs       %s\n", strings.Join(rep.IOCs.DefangedIPs, ", "))
	}
	if len(rep.IOCs.DefangedDomains) > 0 {
		fmt.Fprintf(&b, "  Domains   %s\n", strings.Join(rep.IOCs.DefangedDomains, ", "))
	}
	if len(rep.IOCs.FileHashesSHA256) > 0 {
		fmt.Fprintf(&b, "  SHA-256   %s\n", strings.Join(rep.IOCs.FileHashesSHA256, ", "))
	}
	b.WriteByte('\n')

	// Recommendations
	section(&b, c, "RECOMMENDED ACTIONS")
	for _, r := range rep.Recommendations {
		fmt.Fprintf(&b, "  → %s\n", r)
	}
	return b.String()
}

// RenderBatchTerminal formats a directory batch triage summary table.
func RenderBatchTerminal(bs *model.BatchSummary, useColor bool) string {
	c := newANSI(useColor)
	var b strings.Builder
	fmt.Fprintf(&b, "%sZARF BATCH TRIAGE%s  ·  %s  ·  %d files\n", c.cyan+c.bold, c.reset, bs.Directory, bs.Total)
	fmt.Fprintf(&b, "  %sCRITICAL:%d%s  %sHIGH:%d%s  %sMEDIUM:%d%s  %sLOW:%d%s  %sCLEAN:%d%s\n\n",
		c.red+c.bold, bs.Critical, c.reset,
		c.red, bs.High, c.reset,
		c.yellow, bs.Medium, c.reset,
		c.cyan, bs.Low, c.reset,
		c.green, bs.Clean, c.reset)

	fmt.Fprintf(&b, "  %s%-5s  %-8s  %-30s  %-28s  %s%s\n", c.bold, "SCORE", "VERDICT", "FILE", "FROM", "SUBJECT", c.reset)
	fmt.Fprintf(&b, "  %s%s%s\n", c.gray, strings.Repeat("─", 104), c.reset)
	for _, it := range bs.Items {
		if it.Error != "" {
			fmt.Fprintf(&b, "  %sERR    %-8s  %-30s  %s%s\n", c.red, "ERROR", clip(it.Filename, 30), it.Error, c.reset)
			continue
		}
		vc := verdictColor(c, it.Verdict)
		fmt.Fprintf(&b, "  %s%3d    %-8s%s  %-30s  %-28s  %s\n",
			vc+c.bold, it.Score, it.Verdict, c.reset,
			clip(it.Filename, 30), clip(it.From, 28), clip(it.Subject, 42))
	}
	return b.String()
}

func section(b *strings.Builder, c ansi, title string) {
	lineLen := 76 - len(title)
	if lineLen < 6 {
		lineLen = 6
	}
	fmt.Fprintf(b, "  %s── %s %s%s\n", c.gray, title, strings.Repeat("─", lineLen), c.reset)
}

func sevColor(c ansi, s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return c.red
	case model.SeverityHigh:
		return c.red
	case model.SeverityMedium:
		return c.yellow
	case model.SeverityLow:
		return c.cyan
	default:
		return c.gray
	}
}

func verdictColor(c ansi, v model.Verdict) string {
	switch v {
	case model.VerdictCritical, model.VerdictHigh:
		return c.red
	case model.VerdictMedium:
		return c.yellow
	case model.VerdictLow:
		return c.cyan
	default:
		return c.green
	}
}

func emptyDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func clip(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max-1]) + "…"
}
