package analyzer

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/gorkemguler/zarf/internal/model"
	"github.com/gorkemguler/zarf/internal/parser"
)

var (
	rxAuthMech   = regexp.MustCompile(`(?i)\b(spf|dkim|dmarc|arc|compauth)\s*=\s*([a-z0-9_\-]+)`)
	rxAuthDomain = regexp.MustCompile(`(?i)(?:header\.d|header\.from|smtp\.mailfrom|smtp\.helo)=([^\s;()]+)`)
)

// AnalyzeAuth parses SPF, DKIM, DMARC, and ARC authentication headers AND performs
// real RFC 6376 offline DKIM body-hash (bh=) verification against the raw email body.
func AnalyzeAuth(pe *parser.ParsedEmail) (model.AuthAnalysis, []model.Finding) {
	var aa model.AuthAnalysis
	var findings []model.Finding

	fromAddr := parser.ParseAddress(pe.HeaderMap.Get("From"))
	fromOrg := ""
	if fromAddr != nil {
		fromOrg = OrgDomain(fromAddr.Domain)
	}

	// 1. Parse Authentication-Results and ARC-Authentication-Results
	for _, h := range pe.Headers {
		nameLow := strings.ToLower(h.Name)
		if nameLow == "authentication-results" || nameLow == "arc-authentication-results" {
			aa.AuthHeaderPresent = true
			parseAuthResultsHeader(h.Name, h.Value, &aa)
		} else if nameLow == "received-spf" && aa.SPF == nil {
			aa.AuthHeaderPresent = true
			parseReceivedSPF(h.Value, &aa)
		}
	}

	// 2. Parse and offline-verify every DKIM-Signature header's bh= body hash (RFC 6376)
	dkimIdx := 0
	for _, h := range pe.Headers {
		if strings.EqualFold(h.Name, "DKIM-Signature") {
			dkimIdx++
			chk := verifyDKIMBodyHash(dkimIdx, h.Value, pe.RawBody, fromOrg)
			aa.DKIMSignatures = append(aa.DKIMSignatures, chk)

			if !chk.BodyHashMatch {
				findings = append(findings, model.Finding{
					RuleID:      "AUTH-004",
					Category:    "auth",
					Severity:    model.SeverityCritical,
					Points:      22,
					Title:       fmt.Sprintf("DKIM body hash mismatch (d=%s)", chk.Domain),
					Description: "Offline RFC 6376 canonicalization of the message body does NOT match the DKIM-Signature bh= tag. The email body was altered after signing or the signature header is forged.",
					Evidence:    fmt.Sprintf("d=%s s=%s declared=%s computed=%s", chk.Domain, chk.Selector, chk.DeclaredBodyHash, chk.ComputedBodyHash),
				})
			}
			if chk.WeakAlgorithm {
				findings = append(findings, model.Finding{
					RuleID:      "AUTH-005",
					Category:    "auth",
					Severity:    model.SeverityMedium,
					Points:      8,
					Title:       fmt.Sprintf("Deprecated DKIM algorithm (%s)", chk.Algorithm),
					Description: "The DKIM signature uses SHA-1 (rsa-sha1), which is cryptographically deprecated by RFC 8301.",
					Evidence:    fmt.Sprintf("d=%s a=%s", chk.Domain, chk.Algorithm),
				})
			}
			if chk.BodyLengthLimit > 0 {
				findings = append(findings, model.Finding{
					RuleID:      "AUTH-006",
					Category:    "auth",
					Severity:    model.SeverityMedium,
					Points:      10,
					Title:       "DKIM signature uses body length limit (l= tag)",
					Description: "The DKIM l= tag leaves bytes past the length limit unsigned, enabling DKIM replay / content-append attacks.",
					Evidence:    fmt.Sprintf("d=%s l=%d", chk.Domain, chk.BodyLengthLimit),
				})
			}
			if !chk.CoversFrom {
				findings = append(findings, model.Finding{
					RuleID:      "AUTH-007",
					Category:    "auth",
					Severity:    model.SeverityHigh,
					Points:      15,
					Title:       "DKIM signature does not cover the From header",
					Description: "RFC 6376 requires the From header to be signed; omitting it permits trivial sender spoofing.",
					Evidence:    fmt.Sprintf("d=%s h=%s", chk.Domain, strings.Join(chk.SignedHeaders, ":")),
				})
			}
		}
	}

	// 3. Score SPF / DKIM / DMARC results reported by receiving MTA
	if aa.SPF != nil {
		switch aa.SPF.Status {
		case "fail":
			findings = append(findings, model.Finding{
				RuleID:      "AUTH-001",
				Category:    "auth",
				Severity:    model.SeverityHigh,
				Points:      20,
				Title:       "SPF hard failure (spf=fail)",
				Description: "The sending IP was explicitly unauthorized by the sender domain's SPF policy.",
				Evidence:    aa.SPF.Detail,
			})
		case "softfail":
			findings = append(findings, model.Finding{
				RuleID:      "AUTH-001",
				Category:    "auth",
				Severity:    model.SeverityMedium,
				Points:      12,
				Title:       "SPF soft failure (spf=softfail)",
				Description: "The sending IP did not match the domain's SPF ~all policy.",
				Evidence:    aa.SPF.Detail,
			})
		case "none", "neutral", "permerror":
			findings = append(findings, model.Finding{
				RuleID:      "AUTH-001",
				Category:    "auth",
				Severity:    model.SeverityLow,
				Points:      6,
				Title:       fmt.Sprintf("SPF non-pass (%s)", aa.SPF.Status),
				Description: "No valid passing SPF authorization was recorded for this sender.",
				Evidence:    aa.SPF.Detail,
			})
		}
	}

	if aa.DMARC != nil {
		switch aa.DMARC.Status {
		case "fail":
			findings = append(findings, model.Finding{
				RuleID:      "AUTH-002",
				Category:    "auth",
				Severity:    model.SeverityHigh,
				Points:      22,
				Title:       "DMARC failure (dmarc=fail)",
				Description: "Neither SPF nor DKIM passed with identifier alignment to the visible From domain.",
				Evidence:    aa.DMARC.Detail,
			})
		case "none", "permerror":
			findings = append(findings, model.Finding{
				RuleID:      "AUTH-002",
				Category:    "auth",
				Severity:    model.SeverityLow,
				Points:      4,
				Title:       fmt.Sprintf("DMARC not enforced (%s)", aa.DMARC.Status),
				Description: "The sender domain has no passing DMARC policy recorded.",
				Evidence:    aa.DMARC.Detail,
			})
		}
	}

	dkimAnyPass := false
	dkimAnyFail := false
	for _, d := range aa.DKIM {
		if d.Status == "pass" {
			dkimAnyPass = true
		} else if d.Status == "fail" || d.Status == "permerror" {
			dkimAnyFail = true
		}
	}
	if dkimAnyFail && !dkimAnyPass {
		findings = append(findings, model.Finding{
			RuleID:      "AUTH-003",
			Category:    "auth",
			Severity:    model.SeverityHigh,
			Points:      18,
			Title:       "DKIM verification failed",
			Description: "The receiving mail gateway reported a failing DKIM cryptographic signature.",
		})
	}

	if !aa.AuthHeaderPresent && len(aa.DKIMSignatures) == 0 {
		findings = append(findings, model.Finding{
			RuleID:      "AUTH-008",
			Category:    "auth",
			Severity:    model.SeverityLow,
			Points:      6,
			Title:       "No email authentication headers (SPF/DKIM/DMARC)",
			Description: "Neither Authentication-Results nor DKIM-Signature headers are present.",
		})
	}

	// Build concise human summary
	parts := []string{}
	if aa.SPF != nil {
		parts = append(parts, "SPF="+aa.SPF.Status)
	} else {
		parts = append(parts, "SPF=missing")
	}
	if len(aa.DKIM) > 0 {
		parts = append(parts, "DKIM="+aa.DKIM[0].Status)
	} else if len(aa.DKIMSignatures) > 0 {
		if aa.DKIMSignatures[0].BodyHashMatch {
			parts = append(parts, "DKIM=bh-verified-offline")
		} else {
			parts = append(parts, "DKIM=bh-mismatch")
		}
	} else {
		parts = append(parts, "DKIM=missing")
	}
	if aa.DMARC != nil {
		parts = append(parts, "DMARC="+aa.DMARC.Status)
	} else {
		parts = append(parts, "DMARC=missing")
	}
	aa.Summary = strings.Join(parts, " · ")

	return aa, findings
}

func parseAuthResultsHeader(headerName, val string, aa *model.AuthAnalysis) {
	segments := strings.Split(val, ";")
	isARC := strings.EqualFold(headerName, "ARC-Authentication-Results")

	for _, seg := range segments {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		m := rxAuthMech.FindStringSubmatch(seg)
		if len(m) < 3 {
			continue
		}
		mech := strings.ToLower(m[1])
		status := strings.ToLower(m[2])
		domain := ""
		if dm := rxAuthDomain.FindStringSubmatch(seg); len(dm) >= 2 {
			domain = strings.Trim(dm[1], "\"'<>@ ")
			if at := strings.LastIndexByte(domain, '@'); at >= 0 {
				domain = domain[at+1:]
			}
		}
		res := model.AuthResult{
			Mechanism: mech,
			Status:    status,
			Domain:    strings.ToLower(domain),
			Detail:    seg,
			Source:    headerName,
		}
		if isARC {
			aa.ARC = append(aa.ARC, res)
			continue
		}
		switch mech {
		case "spf":
			if aa.SPF == nil {
				r := res
				aa.SPF = &r
			}
		case "dkim":
			aa.DKIM = append(aa.DKIM, res)
		case "dmarc":
			if aa.DMARC == nil {
				r := res
				aa.DMARC = &r
			}
		case "arc":
			aa.ARC = append(aa.ARC, res)
		case "compauth":
			aa.CompAuth = status
		}
	}
}

func parseReceivedSPF(val string, aa *model.AuthAnalysis) {
	fields := strings.Fields(val)
	if len(fields) == 0 {
		return
	}
	status := strings.ToLower(strings.Trim(fields[0], ";()"))
	aa.SPF = &model.AuthResult{
		Mechanism: "spf",
		Status:    status,
		Detail:    val,
		Source:    "Received-SPF",
	}
}

// verifyDKIMBodyHash implements RFC 6376 §3.4.3 (simple) and §3.4.4 (relaxed) offline bh= verification.
func verifyDKIMBodyHash(idx int, sigVal string, rawBody []byte, fromOrg string) model.DKIMCheck {
	tags := parseTagList(sigVal)
	alg := strings.ToLower(tags["a"])
	if alg == "" {
		alg = "rsa-sha256"
	}
	canon := strings.ToLower(tags["c"])
	if canon == "" {
		canon = "simple/simple"
	}
	bodyCanon := "simple"
	if slash := strings.IndexByte(canon, '/'); slash >= 0 {
		bodyCanon = strings.TrimSpace(canon[slash+1:])
	}

	domain := strings.ToLower(strings.TrimSpace(tags["d"]))
	selector := strings.TrimSpace(tags["s"])
	declaredBH := strings.ReplaceAll(strings.TrimSpace(tags["bh"]), " ", "")

	var signedHeaders []string
	coversFrom := false
	coversSubject := false
	for _, h := range strings.Split(tags["h"], ":") {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		signedHeaders = append(signedHeaders, h)
		if h == "from" {
			coversFrom = true
		}
		if h == "subject" {
			coversSubject = true
		}
	}

	limit := 0
	if lStr, ok := tags["l"]; ok && lStr != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(lStr)); err == nil && n >= 0 {
			limit = n
		}
	}

	canonicalBody := canonicalizeDKIMBody(rawBody, bodyCanon)
	if limit > 0 && limit < len(canonicalBody) {
		canonicalBody = canonicalBody[:limit]
	}

	var computedBH string
	weakAlg := false
	if strings.HasSuffix(alg, "sha1") {
		weakAlg = true
		sum := sha1.Sum(canonicalBody)
		computedBH = base64.StdEncoding.EncodeToString(sum[:])
	} else {
		sum := sha256.Sum256(canonicalBody)
		computedBH = base64.StdEncoding.EncodeToString(sum[:])
	}

	match := declaredBH != "" && computedBH == declaredBH
	aligned := fromOrg != "" && domain != "" && OrgDomain(domain) == fromOrg

	note := "Body hash (bh=) matches raw message body offline; cryptographic signature (b=) requires DNS public key lookup (skipped in offline mode)."
	if !match {
		note = "Offline body hash mismatch: raw body bytes do not match DKIM bh= digest (body modified in transit or forged signature)."
	}

	return model.DKIMCheck{
		Index:            idx,
		Domain:           domain,
		Selector:         selector,
		Algorithm:        alg,
		Canonicalization: canon,
		SignedHeaders:    signedHeaders,
		DeclaredBodyHash: declaredBH,
		ComputedBodyHash: computedBH,
		BodyHashMatch:    match,
		BodyLengthLimit:  limit,
		CoversFrom:       coversFrom,
		CoversSubject:    coversSubject,
		AlignedWithFrom:  aligned,
		WeakAlgorithm:    weakAlg,
		Note:             note,
	}
}

func parseTagList(s string) map[string]string {
	tags := make(map[string]string)
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		eq := strings.IndexByte(part, '=')
		if eq <= 0 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(part[:eq]))
		v := strings.TrimSpace(part[eq+1:])
		tags[k] = v
	}
	return tags
}

// canonicalizeDKIMBody implements RFC 6376 §3.4.3 (simple) & §3.4.4 (relaxed).
func canonicalizeDKIMBody(rawBody []byte, mode string) []byte {
	// Normalize any bare LF or bare CR to CRLF
	norm := bytes.ReplaceAll(rawBody, []byte("\r\n"), []byte("\n"))
	lines := bytes.Split(norm, []byte("\n"))

	// If rawBody ended with a trailing newline, bytes.Split yields a trailing empty slice element.
	if len(rawBody) > 0 && (rawBody[len(rawBody)-1] == '\n') {
		lines = lines[:len(lines)-1]
	}

	if mode == "relaxed" {
		for i, line := range lines {
			lines[i] = relaxBodyLine(line)
		}
	}

	// Trim all trailing empty lines
	for len(lines) > 0 && len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}

	if len(lines) == 0 {
		if mode == "relaxed" {
			return []byte{}
		}
		return []byte("\r\n")
	}

	var buf bytes.Buffer
	for _, line := range lines {
		buf.Write(line)
		buf.WriteString("\r\n")
	}
	return buf.Bytes()
}

func relaxBodyLine(line []byte) []byte {
	// Trim trailing SP / HTAB
	end := len(line)
	for end > 0 && (line[end-1] == ' ' || line[end-1] == '\t') {
		end--
	}
	line = line[:end]

	// Collapse any sequence of SP / HTAB to a single SP
	out := make([]byte, 0, len(line))
	inWSP := false
	for _, b := range line {
		if b == ' ' || b == '\t' {
			if !inWSP {
				out = append(out, ' ')
				inWSP = true
			}
		} else {
			out = append(out, b)
			inWSP = false
		}
	}
	return out
}
