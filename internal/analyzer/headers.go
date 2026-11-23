package analyzer

import (
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/gorkemguler/zarf/internal/model"
	"github.com/gorkemguler/zarf/internal/parser"
)

var freemailDomains = map[string]bool{
	"gmail.com": true, "googlemail.com": true, "yahoo.com": true, "yahoo.co.uk": true,
	"outlook.com": true, "hotmail.com": true, "live.com": true, "msn.com": true,
	"icloud.com": true, "me.com": true, "aol.com": true, "proton.me": true,
	"protonmail.com": true, "yandex.com": true, "yandex.ru": true, "mail.ru": true,
	"zoho.com": true, "gmx.com": true, "gmx.de": true, "tutanota.com": true,
	"tuta.io": true, "fastmail.com": true, "inbox.com": true, "mynet.com": true,
}

var embeddedEmailRe = regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}`)

// AnalyzeHeaders extracts structured header metadata and checks identity spoofing signals.
func AnalyzeHeaders(pe *parser.ParsedEmail, auth *model.AuthAnalysis) (model.HeaderSummary, model.IdentityAnalysis, []model.Finding) {
	hm := pe.HeaderMap
	hs := model.HeaderSummary{
		Subject:        parser.DecodeRFC2047(hm.Get("Subject")),
		Date:           strings.TrimSpace(hm.Get("Date")),
		MessageID:      strings.TrimSpace(hm.Get("Message-Id")),
		From:           parser.ParseAddress(hm.Get("From")),
		Sender:         parser.ParseAddress(hm.Get("Sender")),
		ReplyTo:        parser.ParseAddressList(hm.Get("Reply-To")),
		ReturnPath:     parser.ParseAddress(hm.Get("Return-Path")),
		To:             parser.ParseAddressList(hm.Get("To")),
		CC:             parser.ParseAddressList(hm.Get("Cc")),
		XMailer:        parser.DecodeRFC2047(hm.Get("X-Mailer")),
		UserAgent:      parser.DecodeRFC2047(hm.Get("User-Agent")),
		XOriginatingIP: strings.Trim(strings.TrimSpace(hm.Get("X-Originating-Ip")), "[] "),
		ContentType:    strings.TrimSpace(hm.Get("Content-Type")),
		AllHeaders:     pe.Headers,
	}

	if hs.Date != "" {
		if t, err := parseEmailDate(hs.Date); err == nil {
			hs.ParsedDate = &t
		}
	}

	if hs.MessageID != "" {
		cleanMID := strings.Trim(hs.MessageID, "<> ")
		if at := strings.LastIndexByte(cleanMID, '@'); at >= 0 {
			hs.MessageDomain = strings.ToLower(strings.TrimRight(cleanMID[at+1:], ".> "))
		}
	}

	var id model.IdentityAnalysis
	var findings []model.Finding

	fromDomain := ""
	if hs.From != nil {
		fromDomain = hs.From.Domain
	}
	fromOrg := OrgDomain(fromDomain)
	id.FromDomain = fromDomain

	if hs.ReturnPath != nil && hs.ReturnPath.Domain != "" {
		id.ReturnPathDomain = hs.ReturnPath.Domain
		if fromOrg != "" && OrgDomain(hs.ReturnPath.Domain) != fromOrg {
			id.ReturnPathMismatch = true
			id.Anomalies = append(id.Anomalies, fmt.Sprintf("From (%s) does not align with Return-Path (%s)", fromDomain, hs.ReturnPath.Domain))
			findings = append(findings, model.Finding{
				RuleID:      "HDR-001",
				Category:    "headers",
				Severity:    model.SeverityMedium,
				Points:      10,
				Title:       "From / Return-Path domain mismatch",
				Description: "The visible From domain differs from the SMTP envelope Return-Path (Mail-From) organizational domain, a common signal in spoofing or unauthorized bulk mailers.",
				Evidence:    fmt.Sprintf("From=%s | Return-Path=%s", fromDomain, hs.ReturnPath.Domain),
			})
		}
	}

	// Reply-To mismatch & BEC freemail redirection check
	for _, rt := range hs.ReplyTo {
		if rt.Domain == "" {
			continue
		}
		id.ReplyToDomains = append(id.ReplyToDomains, rt.Domain)
		if fromOrg != "" && OrgDomain(rt.Domain) != fromOrg {
			id.ReplyToMismatch = true
			if freemailDomains[OrgDomain(rt.Domain)] && !freemailDomains[fromOrg] {
				id.ReplyToFreemail = true
			}
		}
	}
	if id.ReplyToFreemail {
		id.Anomalies = append(id.Anomalies, fmt.Sprintf("Corporate From (%s) redirects replies to freemail Reply-To (%s)", fromDomain, strings.Join(id.ReplyToDomains, ", ")))
		findings = append(findings, model.Finding{
			RuleID:      "HDR-002",
			Category:    "headers",
			Severity:    model.SeverityHigh,
			Points:      18,
			Title:       "BEC pattern: Reply-To redirects to external freemail",
			Description: "Replies to a non-freemail sender are silently redirected to a consumer freemail address, a classic Business Email Compromise (CEO/invoice fraud) tactic.",
			Evidence:    fmt.Sprintf("From=%s | Reply-To=%s", fromDomain, strings.Join(id.ReplyToDomains, ", ")),
		})
	} else if id.ReplyToMismatch {
		id.Anomalies = append(id.Anomalies, fmt.Sprintf("From (%s) differs from Reply-To (%s)", fromDomain, strings.Join(id.ReplyToDomains, ", ")))
		findings = append(findings, model.Finding{
			RuleID:      "HDR-003",
			Category:    "headers",
			Severity:    model.SeverityMedium,
			Points:      12,
			Title:       "From / Reply-To domain mismatch",
			Description: "Replying to this message sends correspondence to a different organizational domain than the displayed sender.",
			Evidence:    fmt.Sprintf("From=%s | Reply-To=%s", fromDomain, strings.Join(id.ReplyToDomains, ", ")),
		})
	}

	// Display-name spoofing: embedded email address or brand impersonation
	if hs.From != nil && hs.From.DisplayName != "" {
		if m := embeddedEmailRe.FindString(hs.From.DisplayName); m != "" {
			if !strings.EqualFold(m, hs.From.Address) {
				id.DisplayNameSpoof = true
				id.DisplayNameEmbeddedEmail = m
				id.Anomalies = append(id.Anomalies, fmt.Sprintf("Display name embeds a different email (%s) than actual sender (%s)", m, hs.From.Address))
				findings = append(findings, model.Finding{
					RuleID:      "HDR-004",
					Category:    "headers",
					Severity:    model.SeverityHigh,
					Points:      20,
					Title:       "Display-name email address spoofing",
					Description: "The From display name embeds an email address different from the actual sender address to deceive mobile and webmail clients that hide the real address.",
					Evidence:    fmt.Sprintf("DisplayName=%q | Actual=%s", hs.From.DisplayName, hs.From.Address),
				})
			}
		}

		if brand := MatchDisplayNameBrand(hs.From.DisplayName, fromDomain); brand != "" {
			id.DisplayNameSpoof = true
			id.DisplayNameBrandImpersonat = brand
			id.Anomalies = append(id.Anomalies, fmt.Sprintf("Display name impersonates %s from unrelated domain %s", brand, fromDomain))
			findings = append(findings, model.Finding{
				RuleID:      "HDR-005",
				Category:    "headers",
				Severity:    model.SeverityHigh,
				Points:      18,
				Title:       fmt.Sprintf("Sender display name impersonates %s", brand),
				Description: "The sender's display name references a high-value brand while originating from an unrelated domain.",
				Evidence:    fmt.Sprintf("DisplayName=%q | FromDomain=%s", hs.From.DisplayName, fromDomain),
			})
		}
	}

	// From domain homoglyph / punycode / brand lookalike check
	if fromDomain != "" {
		decoded, hasPuny := DecodePunycodeDomain(fromDomain)
		if hasPuny {
			id.FromPunycodeDecoded = decoded
		}
		isHomo, _, detail := DetectHomoglyph(fromDomain)
		if isHomo {
			id.FromHomoglyph = true
			id.Anomalies = append(id.Anomalies, detail)
			findings = append(findings, model.Finding{
				RuleID:      "HDR-006",
				Category:    "headers",
				Severity:    model.SeverityCritical,
				Points:      25,
				Title:       "Sender domain uses IDN / homoglyph spoofing",
				Description: "The From domain uses Punycode or confusable non-Latin characters designed to visually mimic a trusted domain.",
				Evidence:    fmt.Sprintf("From=%s (%s)", fromDomain, detail),
			})
		} else if brand, reason := MatchImpersonatedBrand(fromDomain); brand != "" {
			id.Anomalies = append(id.Anomalies, reason)
			findings = append(findings, model.Finding{
				RuleID:      "HDR-007",
				Category:    "headers",
				Severity:    model.SeverityHigh,
				Points:      20,
				Title:       fmt.Sprintf("Sender domain mimics %s", brand),
				Description: reason,
				Evidence:    fromDomain,
			})
		}
	}

	// Message-ID domain check
	if fromOrg != "" && hs.MessageDomain != "" && OrgDomain(hs.MessageDomain) != fromOrg {
		id.MessageIDDomainMismatch = true
		findings = append(findings, model.Finding{
			RuleID:      "HDR-008",
			Category:    "headers",
			Severity:    model.SeverityLow,
			Points:      4,
			Title:       "Message-ID domain differs from From domain",
			Description: "The Message-ID host does not align with the sender's organizational domain (can happen with third-party ESPs, but corroborates spoofing when combined with auth failures).",
			Evidence:    fmt.Sprintf("From=%s | Message-ID=%s", fromDomain, hs.MessageID),
		})
	}

	// Missing standard headers
	if hs.From == nil || hs.From.Address == "" {
		findings = append(findings, model.Finding{
			RuleID:      "HDR-009",
			Category:    "headers",
			Severity:    model.SeverityMedium,
			Points:      10,
			Title:       "Missing or malformed From header",
			Description: "The email lacks a valid RFC 5322 From address.",
		})
	}
	if hs.MessageID == "" {
		findings = append(findings, model.Finding{
			RuleID:      "HDR-010",
			Category:    "headers",
			Severity:    model.SeverityLow,
			Points:      5,
			Title:       "Missing Message-ID header",
			Description: "Legitimate mail servers almost always assign a Message-ID; its absence often indicates custom phishing scripts.",
		})
	}

	// Collect DKIM domains for identity matrix
	if auth != nil {
		seen := map[string]bool{}
		for _, sig := range auth.DKIMSignatures {
			if sig.Domain != "" && !seen[sig.Domain] {
				seen[sig.Domain] = true
				id.DKIMDomains = append(id.DKIMDomains, sig.Domain)
			}
		}
	}

	// Suspicious X-Mailer hints (known phishing / bulk frameworks)
	mailer := strings.ToLower(hs.XMailer + " " + hs.UserAgent)
	for _, sig := range []string{"phpmailer", "swiftmailer", "king phisher", "gophish", "setoolkit", "evilginx", "python-smtplib"} {
		if strings.Contains(mailer, sig) {
			sev := model.SeverityMedium
			pts := 8
			if sig == "gophish" || sig == "king phisher" || sig == "setoolkit" || sig == "evilginx" {
				sev = model.SeverityCritical
				pts = 30
			}
			findings = append(findings, model.Finding{
				RuleID:      "HDR-011",
				Category:    "headers",
				Severity:    sev,
				Points:      pts,
				Title:       fmt.Sprintf("Notable mailer fingerprint (%s)", sig),
				Description: "The X-Mailer / User-Agent header matches a scripting library or phishing simulation framework.",
				Evidence:    strings.TrimSpace(hs.XMailer + " " + hs.UserAgent),
			})
			break
		}
	}

	return hs, id, findings
}

// parseEmailDate handles RFC 5322 dates plus common MTA quirks like trailing timezone comments.
func parseEmailDate(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if t, err := mail.ParseDate(s); err == nil {
		return t, nil
	}
	// Strip parenthesized comments like (UTC) or (PDT)
	cleaned := regexp.MustCompile(`\s*\([^)]*\)\s*`).ReplaceAllString(s, " ")
	cleaned = strings.TrimSpace(cleaned)
	if t, err := mail.ParseDate(cleaned); err == nil {
		return t, nil
	}
	layouts := []string{
		"Mon, 2 Jan 2006 15:04:05 -0700",
		"2 Jan 2006 15:04:05 -0700",
		"Mon, 2 Jan 2006 15:04:05 MST",
		"2 Jan 2006 15:04:05 MST",
		time.RFC1123Z,
		time.RFC1123,
		time.RFC3339,
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, cleaned); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unparseable date: %s", s)
}
