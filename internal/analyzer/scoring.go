package analyzer

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gorkemguler/zarf/internal/model"
)

var severityRank = map[model.Severity]int{
	model.SeverityCritical: 5,
	model.SeverityHigh:     4,
	model.SeverityMedium:   3,
	model.SeverityLow:      2,
	model.SeverityInfo:     1,
}

// ComputeRiskScore calculates a transparent, explainable 0-100 risk score and verdict.
func ComputeRiskScore(findings []model.Finding) model.RiskScore {
	cats := map[string]int{
		"headers":     0,
		"auth":        0,
		"hops":        0,
		"body":        0,
		"urls":        0,
		"attachments": 0,
	}

	// Category caps prevent one noisy category from drowning out the rest,
	// while a single critical threat can still push the email into HIGH/CRITICAL.
	caps := map[string]int{
		"headers":     35,
		"auth":        35,
		"hops":        20,
		"body":        45,
		"urls":        45,
		"attachments": 50,
	}

	rawSum := 0
	critCount := 0
	highCount := 0
	for _, f := range findings {
		cats[f.Category] += f.Points
		if f.Severity == model.SeverityCritical {
			critCount++
		} else if f.Severity == model.SeverityHigh {
			highCount++
		}
	}

	for cat, val := range cats {
		if capVal, ok := caps[cat]; ok && val > capVal {
			cats[cat] = capVal
		}
		rawSum += cats[cat]
	}

	// Ensure critical findings always yield at least HIGH (>=65) or CRITICAL (>=80 if multiple)
	if critCount >= 2 && rawSum < 82 {
		rawSum = 82
	} else if critCount == 1 && rawSum < 60 {
		rawSum = 60
	}

	if rawSum > 100 {
		rawSum = 100
	}

	verdict := model.VerdictClean
	switch {
	case rawSum >= 75:
		verdict = model.VerdictCritical
	case rawSum >= 50:
		verdict = model.VerdictHigh
	case rawSum >= 25:
		verdict = model.VerdictMedium
	case rawSum >= 10:
		verdict = model.VerdictLow
	default:
		verdict = model.VerdictClean
	}

	summary := fmt.Sprintf("Score %d/100 (%s) — %d findings (%d critical, %d high)",
		rawSum, verdict, len(findings), critCount, highCount)

	return model.RiskScore{
		Total:      rawSum,
		MaxScore:   100,
		Verdict:    verdict,
		Categories: cats,
		Summary:    summary,
	}
}

// SortFindings orders findings by severity descending, then points descending, then rule ID.
func SortFindings(findings []model.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		ri, rj := severityRank[findings[i].Severity], severityRank[findings[j].Severity]
		if ri != rj {
			return ri > rj
		}
		if findings[i].Points != findings[j].Points {
			return findings[i].Points > findings[j].Points
		}
		return findings[i].RuleID < findings[j].RuleID
	})
}

// ExtractIOCs aggregates all unique observables (IPs, domains, URLs, emails, attachment hashes)
// with both raw and analyst-safe defanged representations.
func ExtractIOCs(rep *model.Report) model.IOCSummary {
	ips := append([]string{}, rep.Hops.PublicIPs...)
	var domains, urls, emails, hashes []string

	if rep.Headers.From != nil && rep.Headers.From.Address != "" {
		emails = append(emails, strings.ToLower(rep.Headers.From.Address))
		if rep.Headers.From.Domain != "" {
			domains = append(domains, rep.Headers.From.Domain)
		}
	}
	if rep.Headers.ReturnPath != nil && rep.Headers.ReturnPath.Address != "" {
		emails = append(emails, strings.ToLower(rep.Headers.ReturnPath.Address))
		if rep.Headers.ReturnPath.Domain != "" {
			domains = append(domains, rep.Headers.ReturnPath.Domain)
		}
	}
	for _, rt := range rep.Headers.ReplyTo {
		if rt.Address != "" {
			emails = append(emails, strings.ToLower(rt.Address))
		}
		if rt.Domain != "" {
			domains = append(domains, rt.Domain)
		}
	}

	for _, u := range rep.URLs {
		urls = append(urls, u.Raw)
		if u.IsIPAddress {
			ips = append(ips, u.Host)
		} else if u.Host != "" {
			domains = append(domains, u.Host)
		}
	}

	for _, att := range rep.Attachments {
		if att.SHA256 != "" {
			hashes = append(hashes, att.SHA256)
		}
	}
	for _, ep := range rep.Body.EmbeddedPayloads {
		if ep.SHA256 != "" && ep.Suspicious {
			hashes = append(hashes, ep.SHA256)
		}
	}

	ips = uniqueStrings(ips)
	domains = uniqueStrings(domains)
	urls = uniqueStrings(urls)
	emails = uniqueStrings(emails)
	hashes = uniqueStrings(hashes)

	defIPs := make([]string, len(ips))
	for i, ip := range ips {
		defIPs[i] = DefangHost(ip)
	}
	defDomains := make([]string, len(domains))
	for i, d := range domains {
		defDomains[i] = DefangHost(d)
	}
	defURLs := make([]string, len(urls))
	for i, u := range urls {
		defURLs[i] = DefangURL(u)
	}

	return model.IOCSummary{
		IPs:              ips,
		DefangedIPs:      defIPs,
		Domains:          domains,
		DefangedDomains:  defDomains,
		URLs:             urls,
		DefangedURLs:     defURLs,
		Emails:           emails,
		FileHashesSHA256: hashes,
	}
}

// BuildRecommendations produces concise, actionable SOC/IR triage steps grounded in the actual findings.
func BuildRecommendations(rep *model.Report) []string {
	var recs []string
	ruleSet := map[string]bool{}
	for _, f := range rep.Findings {
		ruleSet[f.RuleID] = true
	}

	if rep.Score.Verdict == model.VerdictCritical || rep.Score.Verdict == model.VerdictHigh {
		recs = append(recs, "Quarantine this message across all mailboxes and purge matching Message-ID / sender indicators.")
	}
	if ruleSet["HTML-001"] || ruleSet["HTML-003"] || ruleSet["ATT-006"] {
		recs = append(recs, "Do NOT open the HTML/SVG payload in a browser; block client-side HTML smuggling indicators and inspect endpoint download folders.")
	}
	if ruleSet["ATT-002"] || ruleSet["ATT-004"] || ruleSet["ATT-005"] || ruleSet["ATT-009"] || ruleSet["ATT-010"] {
		recs = append(recs, "Submit attachment SHA-256 hashes to EDR/SIEM hunt queries and detonate in an isolated sandbox if dynamic analysis is required.")
	}
	if ruleSet["URL-001"] || ruleSet["URL-002"] || ruleSet["URL-003"] || ruleSet["URL-005"] || ruleSet["HTML-004"] {
		recs = append(recs, "Block malicious lookalike/credential-harvesting domains at DNS/Web proxy, initiate registrar abuse takedown, and check proxy logs for users who clicked.")
	}
	if ruleSet["HDR-002"] || ruleSet["HDR-004"] || ruleSet["HDR-005"] {
		recs = append(recs, "Verify any payment, IBAN, or credential change out-of-band; alert finance/executive targets to active BEC impersonation.")
	}
	if ruleSet["AUTH-001"] || ruleSet["AUTH-002"] || ruleSet["AUTH-004"] {
		recs = append(recs, "Review SPF/DKIM/DMARC gateway enforcement rules and investigate why an unauthenticated or tampered message reached the inbox.")
	}
	if len(recs) == 0 {
		recs = append(recs, "No high-risk phishing indicators detected offline. Verify sender context if unexpected and retain the evidence SHA-256 for auditability.")
	}
	return recs
}
