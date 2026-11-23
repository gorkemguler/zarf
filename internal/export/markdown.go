package export

import (
	"fmt"
	"strings"

	"github.com/gorkemguler/zarf/internal/model"
)

// RenderMarkdown generates a structured SOC / Incident Response triage report in GitHub-Flavored Markdown.
func RenderMarkdown(rep *model.Report) string {
	var b strings.Builder

	fmt.Fprintf(&b, "# Zarf Email Forensic Autopsy Report\n\n")
	fmt.Fprintf(&b, "- **Verdict:** `%s` (**%d / 100**)\n", rep.Score.Verdict, rep.Score.Total)
	fmt.Fprintf(&b, "- **Analyzed At (UTC):** `%s` (Offline Mode: `true`, Zero Network Calls)\n", rep.AnalyzedAt.Format("2006-01-02T15:04:05Z"))
	fmt.Fprintf(&b, "- **Tool:** `zarf v%s`\n\n", rep.ToolVersion)

	fmt.Fprintf(&b, "## Evidence Integrity Manifest\n\n")
	fmt.Fprintf(&b, "| Field | Value |\n| :--- | :--- |\n")
	fmt.Fprintf(&b, "| Filename | `%s` |\n", rep.Evidence.Filename)
	fmt.Fprintf(&b, "| Size | `%d` bytes (%d lines) |\n", rep.Evidence.SizeBytes, rep.Evidence.LineCount)
	fmt.Fprintf(&b, "| SHA-256 | `%s` |\n", rep.Evidence.SHA256)
	fmt.Fprintf(&b, "| SHA-1 | `%s` |\n", rep.Evidence.SHA1)
	fmt.Fprintf(&b, "| MD5 | `%s` |\n\n", rep.Evidence.MD5)

	fmt.Fprintf(&b, "## Envelope & Authentication\n\n")
	fromVal := "-"
	if rep.Headers.From != nil {
		fromVal = fmt.Sprintf("%s <%s>", rep.Headers.From.DisplayName, rep.Headers.From.Address)
	}
	rpVal := "-"
	if rep.Headers.ReturnPath != nil {
		rpVal = rep.Headers.ReturnPath.Address
	}
	fmt.Fprintf(&b, "| Header | Value |\n| :--- | :--- |\n")
	fmt.Fprintf(&b, "| **From** | `%s` |\n", escapeMD(fromVal))
	fmt.Fprintf(&b, "| **Return-Path** | `%s` |\n", escapeMD(rpVal))
	fmt.Fprintf(&b, "| **Subject** | `%s` |\n", escapeMD(rep.Headers.Subject))
	fmt.Fprintf(&b, "| **Date** | `%s` |\n", escapeMD(rep.Headers.Date))
	fmt.Fprintf(&b, "| **Message-ID** | `%s` |\n", escapeMD(rep.Headers.MessageID))
	fmt.Fprintf(&b, "| **Auth Summary** | `%s` |\n\n", rep.Auth.Summary)

	if len(rep.Auth.DKIMSignatures) > 0 {
		fmt.Fprintf(&b, "### Offline RFC 6376 DKIM Body-Hash Checks\n\n")
		fmt.Fprintf(&b, "| # | Domain (`d=`) | Selector (`s=`) | Algorithm | Body Hash (`bh=`) | Aligned |\n| :---: | :--- | :--- | :--- | :---: | :---: |\n")
		for _, d := range rep.Auth.DKIMSignatures {
			status := "MISMATCH"
			if d.BodyHashMatch {
				status = "MATCH"
			}
			fmt.Fprintf(&b, "| %d | `%s` | `%s` | `%s` | **%s** | `%t` |\n", d.Index, d.Domain, d.Selector, d.Algorithm, status, d.AlignedWithFrom)
		}
		b.WriteByte('\n')
	}

	fmt.Fprintf(&b, "## Findings (%d)\n\n", len(rep.Findings))
	if len(rep.Findings) == 0 {
		fmt.Fprintf(&b, "No suspicious phishing indicators detected.\n\n")
	} else {
		fmt.Fprintf(&b, "| Severity | Rule | Points | Title | Evidence |\n| :---: | :---: | :---: | :--- | :--- |\n")
		for _, f := range rep.Findings {
			fmt.Fprintf(&b, "| **%s** | `%s` | +%d | %s | `%s` |\n",
				f.Severity, f.RuleID, f.Points, escapeMD(f.Title), escapeMD(f.Evidence))
		}
		b.WriteByte('\n')
	}

	if len(rep.Hops.Hops) > 0 {
		fmt.Fprintf(&b, "## SMTP Received Hop Chain\n\n")
		fmt.Fprintf(&b, "| Hop | From Host | From IP | By Host | Protocol | TLS | Delta |\n| :---: | :--- | :--- | :--- | :--- | :---: | :---: |\n")
		for _, h := range rep.Hops.Hops {
			delta := "origin"
			if h.DelaySeconds != nil {
				delta = fmt.Sprintf("%+.0fs", *h.DelaySeconds)
				if h.ClockSkew {
					delta += " (SKEW)"
				}
			}
			fmt.Fprintf(&b, "| %d | `%s` | `%s` | `%s` | `%s` | `%t` | `%s` |\n",
				h.Index, escapeMD(h.FromHost), escapeMD(h.FromIP), escapeMD(h.ByHost), escapeMD(h.Protocol), h.TLS, delta)
		}
		b.WriteByte('\n')
	}

	if len(rep.URLs) > 0 {
		fmt.Fprintf(&b, "## Extracted URLs (Defanged)\n\n")
		fmt.Fprintf(&b, "| Severity | Score | Source | Defanged URL | Notes |\n| :---: | :---: | :--- | :--- | :--- |\n")
		for _, u := range rep.URLs {
			fmt.Fprintf(&b, "| **%s** | %d | `%s` | `%s` | %s |\n",
				u.Severity, u.RiskScore, u.Source, escapeMD(u.Defanged), escapeMD(strings.Join(u.Reasons, "; ")))
		}
		b.WriteByte('\n')
	}

	if len(rep.Attachments) > 0 {
		fmt.Fprintf(&b, "## Attachments (Static Forensics)\n\n")
		fmt.Fprintf(&b, "| Severity | Filename | Size | Entropy | Magic | SHA-256 | Findings |\n| :---: | :--- | :---: | :---: | :--- | :--- | :--- |\n")
		for _, a := range rep.Attachments {
			fmt.Fprintf(&b, "| **%s** | `%s` | %d B | %.2f | %s | `%s` | %s |\n",
				a.Severity, escapeMD(a.Filename), a.SizeBytes, a.Entropy, escapeMD(a.DetectedMagic), a.SHA256, escapeMD(strings.Join(a.Reasons, "; ")))
		}
		b.WriteByte('\n')
	}

	fmt.Fprintf(&b, "## Defanged IOCs\n\n```text\n")
	for _, ip := range rep.IOCs.DefangedIPs {
		fmt.Fprintf(&b, "IP: %s\n", ip)
	}
	for _, d := range rep.IOCs.DefangedDomains {
		fmt.Fprintf(&b, "DOMAIN: %s\n", d)
	}
	for _, u := range rep.IOCs.DefangedURLs {
		fmt.Fprintf(&b, "URL: %s\n", u)
	}
	for _, h := range rep.IOCs.FileHashesSHA256 {
		fmt.Fprintf(&b, "SHA256: %s\n", h)
	}
	fmt.Fprintf(&b, "```\n\n")

	fmt.Fprintf(&b, "## Recommended Actions\n\n")
	for _, r := range rep.Recommendations {
		fmt.Fprintf(&b, "- %s\n", r)
	}
	return b.String()
}

func escapeMD(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}
