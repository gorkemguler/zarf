package analyzer

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strings"

	"github.com/gorkemguler/zarf/internal/model"
	"github.com/gorkemguler/zarf/internal/parser"
)

var (
	rxScriptTag    = regexp.MustCompile(`(?is)<script\b[^>]*>(.*?)</script>`)
	rxIframeTag    = regexp.MustCompile(`(?is)<iframe\b[^>]*>`)
	rxObjectEmbed  = regexp.MustCompile(`(?is)<(?:object|embed|applet)\b[^>]*>`)
	rxMetaRefresh  = regexp.MustCompile(`(?is)<meta\b[^>]*http-equiv\s*=\s*["']?refresh["']?[^>]*>`)
	rxFormTag      = regexp.MustCompile(`(?is)<form\b[^>]*>`)
	rxActionAttr   = regexp.MustCompile(`(?i)\baction\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
	rxPasswordInp  = regexp.MustCompile(`(?is)<input\b[^>]*type\s*=\s*["']?password["']?[^>]*>`)
	rxSVGTag       = regexp.MustCompile(`(?is)<svg\b[^>]*>(.*?)</svg>`)
	rxDataURI      = regexp.MustCompile(`(?i)data:([a-z0-9.+\-]+/[a-z0-9.+\-]+)?([^,\s"'<>]*),([A-Za-z0-9+/=_%.\-\s]{16,})`)
	rxHiddenStyle  = regexp.MustCompile(`(?is)<([a-z0-9]+)\b[^>]*style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\.0+)?\b|font-size\s*:\s*0(?:px|pt|em|rem)?\b|font-size\s*:\s*1px|color\s*:\s*transparent|text-indent\s*:\s*-\d{3,}px)[^"']*["'][^>]*>(.*?)</[a-z0-9]+>`)
	rxStripTags    = regexp.MustCompile(`(?is)<[^>]+>`)
	rxEventHandler = regexp.MustCompile(`(?i)\s+on[a-z]+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)`)
	rxRemoteAttr   = regexp.MustCompile(`(?i)(\b(?:src|background|poster)\s*=\s*)(?:"(https?://[^"]+)"|'(https?://[^']+)'|(https?://[^\s>]+))`)
	rxCSSURL       = regexp.MustCompile(`(?i)url\(\s*["']?(https?://[^"')]+)["']?\s*\)`)
	rxJSProto      = regexp.MustCompile(`(?i)\b(href|action|formaction)\s*=\s*(?:"\s*(?:javascript|vbscript|data):[^"]*"|'\s*(?:javascript|vbscript|data):[^']*')`)
	rxUnsafeBlock  = regexp.MustCompile(`(?is)<(script|iframe|object|embed|applet|base|link|meta)\b[^>]*>.*?</(?:script|iframe|object|embed|applet)>|<(?:script|iframe|object|embed|applet|base|link|meta)\b[^>]*/?>`)
)

type smugglingPattern struct {
	Type     string
	Regex    *regexp.Regexp
	Severity model.Severity
	Detail   string
}

var smugglingPatterns = []smugglingPattern{
	{
		Type:     "blob-createObjectURL",
		Regex:    regexp.MustCompile(`(?i)(?:new\s+Blob\s*\(|URL\.createObjectURL|webkitURL\.createObjectURL|msSaveOrOpenBlob|msSaveBlob)`),
		Severity: model.SeverityCritical,
		Detail:   "JavaScript Blob/createObjectURL payload construction (classic HTML smuggling drop mechanism).",
	},
	{
		Type:     "base64-byte-assembly",
		Regex:    regexp.MustCompile(`(?i)(?:atob\s*\([^)]+\)|Uint8Array\s*\(|Uint16Array\s*\(|ArrayBuffer\s*\(|String\.fromCharCode\s*\()`),
		Severity: model.SeverityHigh,
		Detail:   "In-browser base64 decoding or binary buffer assembly typical of HTML smuggling or obfuscated phishing kits.",
	},
	{
		Type:     "js-eval-or-write",
		Regex:    regexp.MustCompile(`(?i)(?:\beval\s*\(|new\s+Function\s*\(|document\.write(?:ln)?\s*\(|unescape\s*\(|decodeURIComponent\s*\([^)]{20,}\))`),
		Severity: model.SeverityHigh,
		Detail:   "Dynamic JavaScript evaluation or DOM injection used to conceal phishing forms or payload droppers.",
	},
	{
		Type:     "auto-download-trigger",
		Regex:    regexp.MustCompile(`(?i)(?:\.download\s*=|<a\b[^>]*\bdownload\b[^>]*href\s*=\s*["'](?:data:|blob:)|\.click\s*\(\s*\))`),
		Severity: model.SeverityHigh,
		Detail:   "Programmatic or data/blob URI file download trigger inside HTML content.",
	},
	{
		Type:     "svg-active-content",
		Regex:    regexp.MustCompile(`(?is)<svg\b[^>]*(?:onload|onerror|onmouseover|onclick)\s*=|<svg\b[^>]*>.*?(?:<script\b|<foreignObject\b)`),
		Severity: model.SeverityCritical,
		Detail:   "SVG containing executable JavaScript event handlers, script tags, or foreignObject HTML injection.",
	},
	{
		Type:     "iframe-srcdoc",
		Regex:    regexp.MustCompile(`(?is)<iframe\b[^>]*(?:srcdoc\s*=|src\s*=\s*["']data:)`),
		Severity: model.SeverityHigh,
		Detail:   "Inline iframe using srcdoc or data: URI to embed hidden phishing or smuggled payloads.",
	},
}

var urgencyKeywords = []struct {
	Label   string
	Pattern *regexp.Regexp
}{
	{"Account suspension threat", regexp.MustCompile(`(?i)\b(?:account\s+(?:will\s+be\s+)?(?:suspended|locked|disabled|terminated)|hesab[ıi]n[ıi]z\s+(?:ask[ıi]ya|kapat[ıi]lacak|bloke))`)},
	{"Immediate / 24h deadline", regexp.MustCompile(`(?i)\b(?:within\s+24\s+hours|immediate\s+action\s+required|urgent\s+verification|24\s+saat\s+i[çc]inde|acil\s+(?:onay|i[şs]lem|g[üu]ncelleme))`)},
	{"Credential / password prompt", regexp.MustCompile(`(?i)\b(?:verify\s+your\s+(?:identity|password|account)|password\s+(?:has\s+)?expir(?:ed|ing)|re-?enter\s+your\s+password|[şs]ifrenizi\s+(?:g[üu]ncelleyin|do[ğg]rulay[ıi]n)|oturumunuz\s+sona)`)},
	{"Wire / IBAN / invoice payment lure", regexp.MustCompile(`(?i)\b(?:updated\s+(?:bank|wire|iban)|urgent\s+wire\s+transfer|overdue\s+invoice|new\s+bank\s+details|g[üu]ncel\s+iban|vadesi\s+ge[çc]mi[şs]\s+fatura|[öo]deme\s+talimat[ıi])`)},
	{"Legal / e-Tebligat / tax scare", regexp.MustCompile(`(?i)\b(?:e-?tebligat|icra\s+takibi|vergi\s+cezas[ıi]|hukuki\s+i[şs]lem|mahkeme\s+celbi|subpoena|legal\s+notice)`)},
}

// AnalyzeBody inspects email plain-text and HTML content for HTML smuggling,
// hidden CSS cloaking, Unicode zero-width/BiDi spoofing, embedded payloads,
// credential harvesting forms, and produces a safe zero-network HTML preview.
func AnalyzeBody(pe *parser.ParsedEmail) (model.BodyAnalysis, []model.Finding) {
	plain := strings.TrimSpace(strings.Join(pe.PlainTexts, "\n\n"))
	rawHTML := strings.TrimSpace(strings.Join(pe.HTMLBodies, "\n\n"))

	ba := model.BodyAnalysis{
		HasPlainText: plain != "",
		HasHTML:      rawHTML != "",
		PlainText:    plain,
		RawHTML:      rawHTML,
		MIMEPieces:   len(pe.Parts),
	}

	var findings []model.Finding

	// 1. Unicode zero-width & BiDi override detection across subject + body
	combinedText := pe.HeaderMap.Get("Subject") + "\n" + plain + "\n" + rawHTML
	zw, bidi := countStealthUnicode(combinedText)
	ba.ZeroWidthCount = zw
	ba.BiDiOverrideCount = bidi

	if bidi > 0 {
		findings = append(findings, model.Finding{
			RuleID:      "HTML-005",
			Category:    "body",
			Severity:    model.SeverityCritical,
			Points:      22,
			Title:       fmt.Sprintf("Bidirectional Unicode override characters detected (%d)", bidi),
			Description: "The message contains Unicode BiDi control characters (such as U+202E RLO) used to visually reverse filenames, URLs, or text.",
			Evidence:    fmt.Sprintf("BiDi control count=%d", bidi),
		})
	}
	if zw >= 5 {
		findings = append(findings, model.Finding{
			RuleID:      "HTML-006",
			Category:    "body",
			Severity:    model.SeverityMedium,
			Points:      10,
			Title:       fmt.Sprintf("Zero-width character obfuscation detected (%d chars)", zw),
			Description: "Excessive zero-width Unicode characters (U+200B/C/D, U+FEFF, U+00AD) are commonly inserted into phishing text to break keyword detection rules.",
			Evidence:    fmt.Sprintf("Zero-width count=%d", zw),
		})
	}

	// 2. HTML Smuggling, script tags, forms, hidden CSS, embedded data: payloads
	if rawHTML != "" {
		smug, payloads := ScanHTMLSmuggling(rawHTML)
		ba.Smuggling = smug
		ba.EmbeddedPayloads = payloads

		// Script tags in email HTML are always abnormal in legitimate email
		if rxScriptTag.MatchString(rawHTML) {
			ba.Smuggling = appendUniqueSmuggling(ba.Smuggling, model.SmugglingIndicator{
				Type:     "inline-script-tag",
				Severity: model.SeverityHigh,
				Evidence: truncateStr(rxScriptTag.FindString(rawHTML), 140),
				Detail:   "Email HTML contains an embedded <script> block.",
			})
		}
		if rxIframeTag.MatchString(rawHTML) {
			ba.Smuggling = appendUniqueSmuggling(ba.Smuggling, model.SmugglingIndicator{
				Type:     "iframe-tag",
				Severity: model.SeverityMedium,
				Evidence: truncateStr(rxIframeTag.FindString(rawHTML), 140),
				Detail:   "Email HTML embeds an <iframe> element.",
			})
		}
		if rxObjectEmbed.MatchString(rawHTML) {
			ba.Smuggling = appendUniqueSmuggling(ba.Smuggling, model.SmugglingIndicator{
				Type:     "object-or-embed-tag",
				Severity: model.SeverityHigh,
				Evidence: truncateStr(rxObjectEmbed.FindString(rawHTML), 140),
				Detail:   "Email HTML embeds an <object>/<embed> tag.",
			})
		}
		if rxMetaRefresh.MatchString(rawHTML) {
			ba.Smuggling = appendUniqueSmuggling(ba.Smuggling, model.SmugglingIndicator{
				Type:     "meta-refresh-redirect",
				Severity: model.SeverityHigh,
				Evidence: truncateStr(rxMetaRefresh.FindString(rawHTML), 140),
				Detail:   "HTML uses <meta http-equiv=refresh> to auto-redirect the reader.",
			})
		}

		// Forms & password inputs
		forms := rxFormTag.FindAllString(rawHTML, -1)
		for _, f := range forms {
			if m := rxActionAttr.FindStringSubmatch(f); len(m) >= 4 {
				act := firstNonEmpty(m[1], m[2], m[3])
				if act != "" {
					ba.FormActions = append(ba.FormActions, act)
				}
			}
		}
		ba.PasswordInputCount = len(rxPasswordInp.FindAllString(rawHTML, -1))

		// Hidden CSS text (spam filter poisoning / hidden canary)
		hiddenMatches := rxHiddenStyle.FindAllStringSubmatch(rawHTML, 10)
		for _, hm := range hiddenMatches {
			if len(hm) >= 3 {
				cleaned := strings.TrimSpace(html.UnescapeString(rxStripTags.ReplaceAllString(hm[2], " ")))
				cleaned = strings.Join(strings.Fields(cleaned), " ")
				if len(cleaned) >= 6 {
					ba.HiddenTextSnippets = append(ba.HiddenTextSnippets, truncateStr(cleaned, 180))
				}
			}
		}

		// Produce zero-network sanitized HTML preview
		sanitized, blockedHosts, blockedCount := SanitizeHTMLOffline(rawHTML)
		ba.SanitizedHTML = sanitized
		ba.BlockedRemoteHosts = blockedHosts
		ba.BlockedRemoteCount = blockedCount

		// Emit scored findings for HTML threats
		critSmug := 0
		highSmug := 0
		var smugTypes []string
		for _, s := range ba.Smuggling {
			smugTypes = append(smugTypes, s.Type)
			if s.Severity == model.SeverityCritical {
				critSmug++
			} else if s.Severity == model.SeverityHigh {
				highSmug++
			}
		}
		if critSmug > 0 {
			findings = append(findings, model.Finding{
				RuleID:      "HTML-001",
				Category:    "body",
				Severity:    model.SeverityCritical,
				Points:      30,
				Title:       "HTML smuggling / active script payload detected in email body",
				Description: "The HTML body contains active client-side smuggling primitives (Blob/createObjectURL/SVG script) designed to reconstruct or drop malicious payloads locally in the browser.",
				Evidence:    strings.Join(smugTypes, ", "),
			})
		} else if highSmug > 0 {
			findings = append(findings, model.Finding{
				RuleID:      "HTML-002",
				Category:    "body",
				Severity:    model.SeverityHigh,
				Points:      20,
				Title:       "Active JavaScript / redirection constructs inside HTML body",
				Description: "The email HTML includes executable script constructs, obfuscated decoding, or auto-refresh redirection.",
				Evidence:    strings.Join(smugTypes, ", "),
			})
		}

		suspPayloads := 0
		var payloadDesc []string
		for _, ep := range ba.EmbeddedPayloads {
			if ep.Suspicious {
				suspPayloads++
				payloadDesc = append(payloadDesc, fmt.Sprintf("%s (%s, %d bytes)", ep.MIMEType, ep.DetectedMagic, ep.SizeBytes))
			}
		}
		if suspPayloads > 0 {
			findings = append(findings, model.Finding{
				RuleID:      "HTML-003",
				Category:    "body",
				Severity:    model.SeverityCritical,
				Points:      25,
				Title:       fmt.Sprintf("Suspicious base64 data: URI payload embedded (%d)", suspPayloads),
				Description: "Decoded embedded data: URI payload contains executable, archive, script, or HTML content commonly used in HTML smuggling.",
				Evidence:    strings.Join(payloadDesc, "; "),
			})
		}

		if ba.PasswordInputCount > 0 {
			findings = append(findings, model.Finding{
				RuleID:      "HTML-004",
				Category:    "body",
				Severity:    model.SeverityCritical,
				Points:      25,
				Title:       "Embedded credential harvesting form (<input type=password>)",
				Description: "Legitimate emails never embed password input forms directly inside an email body; this is a direct credential-harvesting phishing indicator.",
				Evidence:    fmt.Sprintf("password_inputs=%d | form_actions=%v", ba.PasswordInputCount, ba.FormActions),
			})
		} else if len(ba.FormActions) > 0 {
			findings = append(findings, model.Finding{
				RuleID:      "HTML-007",
				Category:    "body",
				Severity:    model.SeverityMedium,
				Points:      10,
				Title:       "External HTML <form> submission inside email body",
				Description: "The email contains an HTML form submitting directly to an external endpoint.",
				Evidence:    strings.Join(ba.FormActions, ", "),
			})
		}

		if len(ba.HiddenTextSnippets) > 0 {
			findings = append(findings, model.Finding{
				RuleID:      "HTML-008",
				Category:    "body",
				Severity:    model.SeverityMedium,
				Points:      8,
				Title:       fmt.Sprintf("Hidden CSS text / cloaking blocks detected (%d)", len(ba.HiddenTextSnippets)),
				Description: "Text is concealed using display:none, opacity:0, or font-size:0 — often used to poison spam classifiers or hide decoy content.",
				Evidence:    ba.HiddenTextSnippets[0],
			})
		}
	}

	// 3. Urgency / social-engineering contextual lures (low points, contextual)
	visibleText := plain + "\n" + html.UnescapeString(rxStripTags.ReplaceAllString(rawHTML, " "))
	for _, uk := range urgencyKeywords {
		if uk.Pattern.MatchString(visibleText) {
			ba.UrgencySignals = append(ba.UrgencySignals, uk.Label)
		}
	}
	if len(ba.UrgencySignals) >= 2 {
		findings = append(findings, model.Finding{
			RuleID:      "HTML-009",
			Category:    "body",
			Severity:    model.SeverityLow,
			Points:      6,
			Title:       "Multiple social-engineering urgency / credential lures",
			Description: "Message wording combines multiple high-pressure phishing cues (suspension threats, urgent deadlines, credential prompts, or payment changes).",
			Evidence:    strings.Join(ba.UrgencySignals, "; "),
		})
	}

	return ba, findings
}

// ScanHTMLSmuggling inspects any HTML or SVG string (email body or attachment) for smuggling TTPs and data: payloads.
func ScanHTMLSmuggling(content string) ([]model.SmugglingIndicator, []model.EmbeddedPayload) {
	var indicators []model.SmugglingIndicator
	var payloads []model.EmbeddedPayload

	for _, sp := range smugglingPatterns {
		if loc := sp.Regex.FindString(content); loc != "" {
			indicators = append(indicators, model.SmugglingIndicator{
				Type:     sp.Type,
				Severity: sp.Severity,
				Evidence: truncateStr(strings.TrimSpace(loc), 140),
				Detail:   sp.Detail,
			})
		}
	}

	// Inspect embedded data: URIs
	matches := rxDataURI.FindAllStringSubmatch(content, 12)
	for _, m := range matches {
		mimeType := strings.ToLower(strings.TrimSpace(m[1]))
		if mimeType == "" {
			mimeType = "text/plain"
		}
		meta := strings.ToLower(m[2])
		rawPayload := m[3]

		var decoded []byte
		encoding := "raw"
		if strings.Contains(meta, "base64") {
			encoding = "base64"
			clean := strings.Map(func(r rune) rune {
				if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '+' || r == '/' || r == '=' {
					return r
				}
				return -1
			}, rawPayload)
			if len(clean) > 2*1024*1024 {
				clean = clean[:2*1024*1024]
			}
			if b, err := base64.StdEncoding.DecodeString(clean); err == nil {
				decoded = b
			} else if b, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(clean, "=")); err == nil {
				decoded = b
			}
		} else {
			if decStr, err := url.QueryUnescape(rawPayload); err == nil {
				decoded = []byte(decStr)
			} else {
				decoded = []byte(rawPayload)
			}
		}
		if len(decoded) == 0 {
			continue
		}

		sum := sha256.Sum256(decoded)
		magicName, magicCat := IdentifyMagic(decoded, "")
		suspicious := false
		var reasons []string

		if magicCat == "executable" || magicCat == "archive" || magicCat == "shortcut" || magicCat == "disk-image" {
			suspicious = true
			reasons = append(reasons, fmt.Sprintf("Decoded data: URI contains %s (%s)", magicCat, magicName))
		}
		if strings.Contains(mimeType, "html") || strings.Contains(mimeType, "javascript") || strings.Contains(mimeType, "octet-stream") || strings.Contains(mimeType, "svg") {
			suspicious = true
			reasons = append(reasons, fmt.Sprintf("High-risk data: URI MIME type (%s)", mimeType))
		}
		if magicCat == "html" || magicCat == "svg" {
			if rxScriptTag.Match(decoded) || strings.Contains(strings.ToLower(string(decoded)), "onload=") {
				suspicious = true
				reasons = append(reasons, "Decoded data: URI contains active HTML/SVG script")
			}
		}

		snippet := ""
		if magicCat == "text" || magicCat == "html" || magicCat == "svg" || magicCat == "script" {
			snippet = truncateStr(strings.TrimSpace(string(decoded)), 160)
		}

		payloads = append(payloads, model.EmbeddedPayload{
			MIMEType:      mimeType,
			Encoding:      encoding,
			SizeBytes:     len(decoded),
			SHA256:        hex.EncodeToString(sum[:]),
			DetectedMagic: magicName,
			Snippet:       snippet,
			Suspicious:    suspicious,
			Reasons:       reasons,
		})
	}

	return indicators, payloads
}

// SanitizeHTMLOffline strips executable elements, event handlers, and all external remote fetches
// so the email can be visually inspected inside a sandboxed iframe with ZERO network calls.
func SanitizeHTMLOffline(raw string) (sanitized string, blockedHosts []string, blockedCount int) {
	s := rxUnsafeBlock.ReplaceAllString(raw, "<!-- [zarf: stripped active tag] -->")
	s = rxEventHandler.ReplaceAllString(s, "")
	s = rxJSProto.ReplaceAllString(s, `$1="#zarf-blocked"`)

	hostSet := map[string]bool{}
	recordHost := func(rawURL string) {
		blockedCount++
		if u, err := url.Parse(rawURL); err == nil && u.Hostname() != "" {
			h := strings.ToLower(u.Hostname())
			if !hostSet[h] {
				hostSet[h] = true
				blockedHosts = append(blockedHosts, h)
			}
		}
	}

	// Replace remote img/background/poster src with an inline offline SVG placeholder
	s = rxRemoteAttr.ReplaceAllStringFunc(s, func(match string) string {
		sub := rxRemoteAttr.FindStringSubmatch(match)
		if len(sub) < 5 {
			return match
		}
		attrPrefix := sub[1]
		target := firstNonEmpty(sub[2], sub[3], sub[4])
		recordHost(target)
		return attrPrefix + `"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='180' height='28'%3E%3Crect width='100%25' height='100%25' fill='%231e2430' stroke='%23ef4444' stroke-dasharray='3,2'/%3E%3Ctext x='8' y='18' fill='%23f87171' font-family='monospace' font-size='10'%3E[BLOCKED REMOTE IMG]%3C/text%3E%3C/svg%3E"`
	})

	s = rxCSSURL.ReplaceAllStringFunc(s, func(match string) string {
		sub := rxCSSURL.FindStringSubmatch(match)
		if len(sub) >= 2 {
			recordHost(sub[1])
		}
		return "none"
	})

	return s, blockedHosts, blockedCount
}

func countStealthUnicode(s string) (zeroWidth int, bidi int) {
	for _, r := range s {
		switch r {
		case 0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD:
			zeroWidth++
		case 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069:
			bidi++
		}
	}
	return zeroWidth, bidi
}

func appendUniqueSmuggling(list []model.SmugglingIndicator, item model.SmugglingIndicator) []model.SmugglingIndicator {
	for _, existing := range list {
		if existing.Type == item.Type {
			return list
		}
	}
	return append(list, item)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func truncateStr(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
