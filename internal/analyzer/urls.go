package analyzer

import (
	"fmt"
	"html"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/gorkemguler/zarf/internal/model"
	"github.com/gorkemguler/zarf/internal/parser"
)

var (
	rxAnchorTag  = regexp.MustCompile(`(?is)<a\b[^>]*href\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>(.*?)</a>`)
	rxAttrURL    = regexp.MustCompile(`(?i)\b(?:href|src|action|formaction)\s*=\s*(?:"(https?://[^"]+)"|'(https?://[^']+)'|(https?://[^\s>]+))`)
	rxPlainURL   = regexp.MustCompile(`(?i)\bhttps?://[^\s<>"'\)\]]+`)
	rxMetaURL    = regexp.MustCompile(`(?i)url\s*=\s*['"]?(https?://[^'">\s]+)`)
	rxLooksHost  = regexp.MustCompile(`(?i)^(?:https?://)?([a-z0-9\-]+(?:\.[a-z0-9\-]+)+)(?:/.*)?$`)
)

var urlShorteners = map[string]bool{
	"bit.ly": true, "tinyurl.com": true, "t.co": true, "goo.gl": true, "ow.ly": true,
	"is.gd": true, "buff.ly": true, "rebrand.ly": true, "cutt.ly": true, "rb.gy": true,
	"tiny.cc": true, "shorturl.at": true, "t.ly": true, "s.id": true, "bit.do": true,
	"bl.ink": true, "lnkd.in": true, "v.gd": true, "qr.ae": true, "adf.ly": true,
}

var suspiciousTLDs = map[string]bool{
	"xyz": true, "top": true, "click": true, "loan": true, "work": true, "gq": true,
	"ml": true, "cf": true, "tk": true, "ga": true, "zip": true, "mov": true,
	"cfd": true, "sbs": true, "icu": true, "buzz": true, "rest": true, "quest": true,
	"monster": true, "cam": true, "cyou": true, "shop": true, "support": true,
	"autos": true, "beauty": true, "bond": true, "skin": true, "ru": true,
}

var phishPathHints = []string{
	"/login", "/signin", "/sign-in", "/verify", "/validation", "/update-account",
	"/owa", "/webmail", "/office365", "/microsoft", "/billing", "/invoice", "/iban",
	"/giris", "/dogrulama", "/onay", "/hesap", "/sifre", "/wp-includes/", "/wp-content/",
}

var redirectParamNames = []string{"url", "u", "redirect", "redirect_uri", "next", "target", "goto", "dest", "destination", "r", "link", "continue"}

type rawURLRef struct {
	URL        string
	Source     string
	AnchorText string
}

// AnalyzeURLs extracts, decodes, inspects, and scores every URL across HTML, plain text,
// form actions, and attachments (e.g. PDF /URI or HTML attachments).
func AnalyzeURLs(pe *parser.ParsedEmail, body model.BodyAnalysis, attachmentURLs []string, senderDomain string) ([]model.URLFinding, []model.Finding) {
	var refs []rawURLRef

	// 1. HTML anchors (preserves visible anchor text for mismatch checks)
	if body.RawHTML != "" {
		for _, m := range rxAnchorTag.FindAllStringSubmatch(body.RawHTML, -1) {
			href := html.UnescapeString(firstNonEmpty(m[1], m[2], m[3]))
			if !strings.HasPrefix(strings.ToLower(href), "http://") && !strings.HasPrefix(strings.ToLower(href), "https://") {
				continue
			}
			anchorText := strings.TrimSpace(html.UnescapeString(rxStripTags.ReplaceAllString(m[4], " ")))
			anchorText = strings.Join(strings.Fields(anchorText), " ")
			refs = append(refs, rawURLRef{URL: cleanTrailingPunct(href), Source: "html-href", AnchorText: truncateStr(anchorText, 120)})
		}

		// Form actions
		for _, act := range body.FormActions {
			if strings.HasPrefix(strings.ToLower(act), "http://") || strings.HasPrefix(strings.ToLower(act), "https://") {
				refs = append(refs, rawURLRef{URL: cleanTrailingPunct(act), Source: "html-form"})
			}
		}

		// Meta refresh targets
		for _, mm := range rxMetaRefresh.FindAllString(body.RawHTML, -1) {
			if um := rxMetaURL.FindStringSubmatch(mm); len(um) >= 2 {
				refs = append(refs, rawURLRef{URL: cleanTrailingPunct(um[1]), Source: "meta-refresh"})
			}
		}

		// Other HTML attributes (src, href outside anchors, etc.)
		for _, m := range rxAttrURL.FindAllStringSubmatch(body.RawHTML, -1) {
			u := html.UnescapeString(firstNonEmpty(m[1], m[2], m[3]))
			refs = append(refs, rawURLRef{URL: cleanTrailingPunct(u), Source: "html-attr"})
		}
	}

	// 2. Plain text URLs
	if body.PlainText != "" {
		for _, u := range rxPlainURL.FindAllString(body.PlainText, -1) {
			refs = append(refs, rawURLRef{URL: cleanTrailingPunct(u), Source: "plain-text"})
		}
	}

	// 3. Attachment-extracted URLs
	for _, u := range attachmentURLs {
		refs = append(refs, rawURLRef{URL: cleanTrailingPunct(u), Source: "attachment"})
	}

	// Deduplicate by (rawURL, source precedence: html-form > html-href > attachment > plain-text > html-attr)
	seen := map[string]*model.URLFinding{}
	order := []string{}

	for _, ref := range refs {
		if ref.URL == "" {
			continue
		}
		if existing, ok := seen[ref.URL]; ok {
			// Preserve anchor text if the earlier occurrence didn't have one
			if existing.AnchorText == "" && ref.AnchorText != "" {
				existing.AnchorText = ref.AnchorText
				checkAnchorMismatch(existing)
			}
			continue
		}
		uf := inspectSingleURL(ref)
		if uf == nil {
			continue
		}
		seen[ref.URL] = uf
		order = append(order, ref.URL)
	}

	results := make([]model.URLFinding, 0, len(order))
	for _, k := range order {
		results = append(results, *seen[k])
	}

	// Aggregate rule-level findings across all extracted URLs
	var findings []model.Finding
	var homoglyphs, mismatches, brandLookalikes, rawIPs, shorteners, redirects, userinfoURLs []string

	for _, u := range results {
		if u.IsHomoglyph || u.IsPunycode {
			homoglyphs = append(homoglyphs, fmt.Sprintf("%s -> %s", u.Host, u.DecodedHost))
		}
		if u.AnchorMismatch {
			mismatches = append(mismatches, fmt.Sprintf("text=%q -> host=%s", u.AnchorText, u.Host))
		}
		if u.ImpersonatedBrand != "" {
			brandLookalikes = append(brandLookalikes, fmt.Sprintf("%s (%s)", u.Host, u.ImpersonatedBrand))
		}
		if u.IsIPAddress {
			rawIPs = append(rawIPs, u.Defanged)
		}
		if u.HasUserInfoAt {
			userinfoURLs = append(userinfoURLs, u.Defanged)
		}
		if u.IsShortener {
			shorteners = append(shorteners, u.Defanged)
		}
		if u.RedirectTarget != "" {
			redirects = append(redirects, fmt.Sprintf("%s -> %s", u.Host, DefangURL(u.RedirectTarget)))
		}
	}

	if len(homoglyphs) > 0 {
		findings = append(findings, model.Finding{
			RuleID:      "URL-001",
			Category:    "urls",
			Severity:    model.SeverityCritical,
			Points:      25,
			Title:       fmt.Sprintf("IDN / Homoglyph lookalike URL detected (%d)", len(homoglyphs)),
			Description: "One or more links use Punycode (xn--) or mixed-script confusable Unicode characters to visually impersonate a trusted domain.",
			Evidence:    strings.Join(uniqueStrings(homoglyphs), "; "),
		})
	}
	if len(mismatches) > 0 {
		findings = append(findings, model.Finding{
			RuleID:      "URL-002",
			Category:    "urls",
			Severity:    model.SeverityHigh,
			Points:      20,
			Title:       fmt.Sprintf("Deceptive anchor text vs href mismatch (%d)", len(mismatches)),
			Description: "A visible link displays one domain or URL in the anchor text while the underlying href points to a completely different organizational domain.",
			Evidence:    strings.Join(uniqueStrings(mismatches), "; "),
		})
	}
	if len(brandLookalikes) > 0 {
		findings = append(findings, model.Finding{
			RuleID:      "URL-003",
			Category:    "urls",
			Severity:    model.SeverityHigh,
			Points:      18,
			Title:       fmt.Sprintf("Brand-impersonating lookalike link (%d)", len(brandLookalikes)),
			Description: "Link targets a domain that mimics a known brand (combosquatting, typosquatting, or homoglyph skeleton) outside its official domains.",
			Evidence:    strings.Join(uniqueStrings(brandLookalikes), "; "),
		})
	}
	if len(rawIPs) > 0 {
		findings = append(findings, model.Finding{
			RuleID:      "URL-004",
			Category:    "urls",
			Severity:    model.SeverityHigh,
			Points:      18,
			Title:       fmt.Sprintf("Direct IP-address URL (%d)", len(rawIPs)),
			Description: "Link navigates directly to a raw IP address instead of a domain name, commonly seen in transient phishing kits and C2 payload staging.",
			Evidence:    strings.Join(uniqueStrings(rawIPs), ", "),
		})
	}
	if len(userinfoURLs) > 0 {
		findings = append(findings, model.Finding{
			RuleID:      "URL-005",
			Category:    "urls",
			Severity:    model.SeverityCritical,
			Points:      22,
			Title:       "URL uses '@' userinfo authority spoofing",
			Description: "The URL embeds a fake domain before an '@' sign so browsers actually connect to the attacker host after '@'.",
			Evidence:    strings.Join(uniqueStrings(userinfoURLs), ", "),
		})
	}
	if len(shorteners) > 0 {
		findings = append(findings, model.Finding{
			RuleID:      "URL-006",
			Category:    "urls",
			Severity:    model.SeverityMedium,
			Points:      10,
			Title:       fmt.Sprintf("URL shortener conceals destination (%d)", len(shorteners)),
			Description: "Shortened links hide the true landing page from the recipient and bypass static domain filters.",
			Evidence:    strings.Join(uniqueStrings(shorteners), ", "),
		})
	}
	if len(redirects) > 0 {
		findings = append(findings, model.Finding{
			RuleID:      "URL-007",
			Category:    "urls",
			Severity:    model.SeverityMedium,
			Points:      10,
			Title:       fmt.Sprintf("Open-redirect / nested URL wrapper detected (%d)", len(redirects)),
			Description: "A link embeds another destination URL inside query parameters to piggyback on a benign host's reputation.",
			Evidence:    strings.Join(uniqueStrings(redirects), "; "),
		})
	}

	return results, findings
}

func inspectSingleURL(ref rawURLRef) *model.URLFinding {
	u, err := url.Parse(ref.URL)
	if err != nil || u.Host == "" {
		return nil
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return nil
	}

	uf := &model.URLFinding{
		Raw:        ref.URL,
		Defanged:   DefangURL(ref.URL),
		Scheme:     strings.ToLower(u.Scheme),
		Host:       host,
		Path:       u.Path,
		Source:     ref.Source,
		AnchorText: ref.AnchorText,
	}

	score := 0
	addReason := func(pts int, reason string) {
		score += pts
		uf.Reasons = append(uf.Reasons, reason)
	}

	// 1. Userinfo "@" trick
	if u.User != nil && u.User.String() != "" {
		uf.HasUserInfoAt = true
		addReason(35, fmt.Sprintf("Embeds userinfo %q before '@' to spoof host", u.User.String()))
	}

	// 2. Direct IP address (including decimal/hex integer IP encoding)
	if isHostIPAddress(host) {
		uf.IsIPAddress = true
		addReason(30, "Direct IP-based URL without domain name")
	}

	// 3. Punycode + Homoglyph detection
	decoded, hasPuny := DecodePunycodeDomain(host)
	uf.DecodedHost = decoded
	uf.IsPunycode = hasPuny
	isHomo, _, detail := DetectHomoglyph(host)
	uf.IsHomoglyph = isHomo
	uf.HomoglyphDetail = detail
	if isHomo {
		addReason(40, detail)
	} else if hasPuny {
		addReason(20, fmt.Sprintf("Punycode IDN domain decodes to %q", decoded))
	}

	// 4. Brand impersonation check
	if brand, reason := MatchImpersonatedBrand(host); brand != "" {
		uf.ImpersonatedBrand = brand
		addReason(30, reason)
	}

	// 5. Shortener check
	if urlShorteners[OrgDomain(host)] || urlShorteners[host] {
		uf.IsShortener = true
		addReason(18, "Known URL shortener hides true destination")
	}

	// 6. Suspicious TLD check
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		tld := parts[len(parts)-1]
		if suspiciousTLDs[tld] {
			uf.SuspiciousTLD = true
			addReason(12, fmt.Sprintf("High-abuse TLD (.%s)", tld))
		}
	}

	// 7. Open-redirect / embedded URL parameter unwrapping
	q := u.Query()
	for _, key := range redirectParamNames {
		if val := strings.TrimSpace(q.Get(key)); val != "" {
			if unesc, err := url.QueryUnescape(val); err == nil {
				val = unesc
			}
			if strings.HasPrefix(strings.ToLower(val), "http://") || strings.HasPrefix(strings.ToLower(val), "https://") {
				uf.RedirectTarget = val
				addReason(18, fmt.Sprintf("Redirects via ?%s= to %s", key, DefangURL(val)))
				break
			}
		}
	}

	// 8. Credential/phishing path hints + cleartext HTTP
	lowPath := strings.ToLower(u.Path + "?" + u.RawQuery)
	for _, hint := range phishPathHints {
		if strings.Contains(lowPath, hint) {
			addReason(10, fmt.Sprintf("Credential/phishing path token (%s)", hint))
			break
		}
	}
	if uf.Scheme == "http" && (uf.Source == "html-form" || score > 0) {
		addReason(10, "Unencrypted HTTP transport for suspicious/form URL")
	}
	if uf.Source == "html-form" {
		addReason(20, "Target of embedded HTML <form> submission")
	}
	if uf.Source == "meta-refresh" {
		addReason(20, "Target of automatic <meta http-equiv=refresh> redirect")
	}

	// 9. Anchor text vs actual href mismatch
	uf.RiskScore = score
	checkAnchorMismatch(uf)

	// Cap & map severity
	if uf.RiskScore > 100 {
		uf.RiskScore = 100
	}
	uf.Severity = scoreToSeverity(uf.RiskScore)
	return uf
}

func checkAnchorMismatch(uf *model.URLFinding) {
	if uf.AnchorText == "" {
		return
	}
	cand := strings.TrimSpace(uf.AnchorText)
	m := rxLooksHost.FindStringSubmatch(cand)
	if len(m) < 2 {
		return
	}
	displayedHost := strings.ToLower(m[1])
	// Ignore if displayedHost doesn't look like a domain with a valid TLD
	parts := strings.Split(displayedHost, ".")
	if len(parts) < 2 || len(parts[len(parts)-1]) < 2 || len(parts[len(parts)-1]) > 12 {
		return
	}
	if OrgDomain(displayedHost) != OrgDomain(uf.Host) {
		uf.AnchorMismatch = true
		uf.RiskScore += 35
		uf.Reasons = append(uf.Reasons, fmt.Sprintf("Anchor text claims %q but href navigates to %q", displayedHost, uf.Host))
		if uf.RiskScore > 100 {
			uf.RiskScore = 100
		}
		uf.Severity = scoreToSeverity(uf.RiskScore)
	}
}

func isHostIPAddress(host string) bool {
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	// Check decimal-encoded IPv4 (e.g. http://3232235777/) or hex IPv4 (0x7f000001)
	if strings.HasPrefix(host, "0x") {
		if _, err := strconv.ParseUint(host[2:], 16, 32); err == nil {
			return true
		}
	}
	if len(host) >= 8 && len(host) <= 10 {
		if v, err := strconv.ParseUint(host, 10, 32); err == nil && v > 16777216 {
			return true
		}
	}
	return false
}

func cleanTrailingPunct(u string) string {
	return strings.TrimRight(strings.TrimSpace(u), ".,;:!?)>]\"'")
}

func scoreToSeverity(score int) model.Severity {
	switch {
	case score >= 60:
		return model.SeverityCritical
	case score >= 35:
		return model.SeverityHigh
	case score >= 18:
		return model.SeverityMedium
	case score >= 5:
		return model.SeverityLow
	default:
		return model.SeverityInfo
	}
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
