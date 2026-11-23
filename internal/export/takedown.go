package export

import (
	"fmt"
	"strings"

	"github.com/gorkemguler/zarf/internal/model"
)

// RenderTakedownDraft produces a clean, evidence-backed Abuse / Phishing Takedown notice
// ready to send to hosting providers, registrars, or CERT/TR-CERT abuse desks.
func RenderTakedownDraft(rep *model.Report, lang string) string {
	var b strings.Builder

	var suspURLs []string
	var suspDomains []string
	seenDom := map[string]bool{}
	for _, u := range rep.URLs {
		if u.RiskScore >= 20 {
			suspURLs = append(suspURLs, u.Defanged)
			if !seenDom[u.Host] {
				seenDom[u.Host] = true
				suspDomains = append(suspDomains, u.Host)
			}
		}
	}
	if rep.Identity.FromHomoglyph || rep.Identity.DisplayNameSpoof {
		if rep.Identity.FromDomain != "" && !seenDom[rep.Identity.FromDomain] {
			seenDom[rep.Identity.FromDomain] = true
			suspDomains = append(suspDomains, rep.Identity.FromDomain)
		}
	}

	targetSummary := strings.ReplaceAll(strings.Join(suspDomains, ", "), ".", "[.]")
	if targetSummary == "" {
		targetSummary = strings.ReplaceAll(rep.Identity.FromDomain, ".", "[.]")
	}

	if strings.EqualFold(lang, "tr") {
		fmt.Fprintf(&b, "Konu: Oltalama (Phishing) / Zararlı İçerik İhbarı ve Erişim Kaldırma Talebi — %s\n\n", targetSummary)
		fmt.Fprintf(&b, "Sayın Abuse / Güvenlik Ekibi,\n\n")
		fmt.Fprintf(&b, "Aşağıda teknik kanıtları sunulan e-posta üzerinden aktif bir oltalama (phishing) / marka taklidi faaliyeti tespit edilmiştir. İlgili alan adı/altyapı için inceleme ve acil kaldırma (takedown) işlemi yapılmasını rica ederiz.\n\n")
		fmt.Fprintf(&b, "=== ÖZET KANIT PAKETİ ===\n")
		fmt.Fprintf(&b, "Analiz Tarihi (UTC) : %s\n", rep.AnalyzedAt.UTC().Format("2006-01-02 15:04:05Z"))
		fmt.Fprintf(&b, "E-posta SHA-256     : %s\n", rep.Evidence.SHA256)
		fmt.Fprintf(&b, "Risk Skoru          : %d/100 (%s)\n", rep.Score.Total, rep.Score.Verdict)
		if rep.Hops.OriginIP != "" {
			fmt.Fprintf(&b, "Kaynak IP           : %s\n", strings.ReplaceAll(rep.Hops.OriginIP, ".", "[.]"))
		}
		if len(suspDomains) > 0 {
			fmt.Fprintf(&b, "Şüpheli Alan Adları : %s\n", strings.ReplaceAll(strings.Join(suspDomains, ", "), ".", "[.]"))
		}
		if len(suspURLs) > 0 {
			fmt.Fprintf(&b, "\nDefanged Şüpheli URL'ler:\n")
			for _, u := range suspURLs {
				fmt.Fprintf(&b, "  - %s\n", u)
			}
		}
		fmt.Fprintf(&b, "\nTespit Edilen Teknik Bulgular:\n")
		for i, f := range rep.Findings {
			if i >= 6 {
				break
			}
			fmt.Fprintf(&b, "  - [%s/%s] %s (%s)\n", f.RuleID, f.Severity, f.Title, f.Evidence)
		}
		fmt.Fprintf(&b, "\nSaygılarımızla,\nSOC / Threat Intelligence Ekibi (Zarf v%s ile üretilmiştir)\n", rep.ToolVersion)
		return b.String()
	}

	fmt.Fprintf(&b, "Subject: Phishing / Brand Impersonation Abuse Report & Takedown Request — %s\n\n", targetSummary)
	fmt.Fprintf(&b, "Hello Abuse / Trust & Safety Team,\n\n")
	fmt.Fprintf(&b, "We are reporting active phishing / brand impersonation infrastructure observed in a captured malicious email. Please investigate and suspend the offending resources listed below.\n\n")
	fmt.Fprintf(&b, "=== FORENSIC EVIDENCE SUMMARY ===\n")
	fmt.Fprintf(&b, "Observed / Analyzed (UTC) : %s\n", rep.AnalyzedAt.UTC().Format("2006-01-02 15:04:05Z"))
	fmt.Fprintf(&b, "Raw EML SHA-256           : %s\n", rep.Evidence.SHA256)
	fmt.Fprintf(&b, "Forensic Risk Score       : %d/100 (%s)\n", rep.Score.Total, rep.Score.Verdict)
	if rep.Hops.OriginIP != "" {
		fmt.Fprintf(&b, "Originating Relay IP      : %s\n", strings.ReplaceAll(rep.Hops.OriginIP, ".", "[.]"))
	}
	if len(suspDomains) > 0 {
		fmt.Fprintf(&b, "Offending Domain(s)       : %s\n", strings.ReplaceAll(strings.Join(suspDomains, ", "), ".", "[.]"))
	}
	if len(suspURLs) > 0 {
		fmt.Fprintf(&b, "\nDefanged Phishing URL(s):\n")
		for _, u := range suspURLs {
			fmt.Fprintf(&b, "  - %s\n", u)
		}
	}
	fmt.Fprintf(&b, "\nKey Technical Indicators:\n")
	for i, f := range rep.Findings {
		if i >= 6 {
			break
		}
		fmt.Fprintf(&b, "  - [%s/%s] %s (%s)\n", f.RuleID, f.Severity, f.Title, f.Evidence)
	}
	fmt.Fprintf(&b, "\nFull RFC 5322 headers and SHA-256 integrity manifest are available upon request.\n\nBest regards,\nSOC / Threat Intelligence Team (generated offline with Zarf v%s)\n", rep.ToolVersion)
	return b.String()
}
