package analyzer

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/gorkemguler/zarf/internal/model"
	"github.com/gorkemguler/zarf/internal/samples"
)

func TestPunycodeAndHomoglyphDetection(t *testing.T) {
	cases := []struct {
		domain       string
		wantDecoded  string
		wantHomo     bool
		wantBrand    string
	}{
		{"xn--micrsoft-qbh.xyz", "micrоsoft.xyz", true, "Microsoft"},
		{"xn--pple-43d.com", "аpple.com", true, "Apple"},
		{"xn--grantibbva-zqi.top", "gаrantibbva.top", true, "Garanti BBVA"},
		{"microsoft.com", "microsoft.com", false, ""},
		{"garantibbva.com.tr", "garantibbva.com.tr", false, ""},
	}

	for _, tc := range cases {
		dec, _ := DecodePunycodeDomain(tc.domain)
		if dec != tc.wantDecoded {
			t.Errorf("DecodePunycodeDomain(%q) = %q, want %q", tc.domain, dec, tc.wantDecoded)
		}
		isHomo, _, _ := DetectHomoglyph(tc.domain)
		if isHomo != tc.wantHomo {
			t.Errorf("DetectHomoglyph(%q) = %v, want %v", tc.domain, isHomo, tc.wantHomo)
		}
		brand, _ := MatchImpersonatedBrand(tc.domain)
		if brand != tc.wantBrand {
			t.Errorf("MatchImpersonatedBrand(%q) = %q, want %q", tc.domain, brand, tc.wantBrand)
		}
	}
}

func TestOrgDomainMultiPartTLDs(t *testing.T) {
	if got := OrgDomain("mail.garantibbva.com.tr"); got != "garantibbva.com.tr" {
		t.Fatalf("expected garantibbva.com.tr, got %s", got)
	}
	if got := OrgDomain("sub.turkiye.gov.tr"); got != "turkiye.gov.tr" {
		t.Fatalf("expected turkiye.gov.tr, got %s", got)
	}
	if got := OrgDomain("mail.corp.co.uk"); got != "corp.co.uk" {
		t.Fatalf("expected corp.co.uk, got %s", got)
	}
}

func TestOfflineDKIMBodyHashVerification(t *testing.T) {
	body := "Line one   with   spaces   \r\nLine two\t\r\n\r\n\r\n"
	// Under RFC 6376 relaxed canonicalization:
	// "Line one with spaces\r\nLine two\r\n"
	expectedCanon := "Line one with spaces\r\nLine two\r\n"
	sum := sha256.Sum256([]byte(expectedCanon))
	bh := base64.StdEncoding.EncodeToString(sum[:])

	rawGood := "From: alice@corp.example\r\n" +
		"To: bob@corp.example\r\n" +
		"Subject: Test\r\n" +
		"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=corp.example; s=sel1; h=from:to:subject; bh=" + bh + "; b=FAKE\r\n" +
		"\r\n" + body

	rep, err := AnalyzeBytes("dkim_good.eml", []byte(rawGood))
	if err != nil {
		t.Fatalf("AnalyzeBytes failed: %v", err)
	}
	if len(rep.Auth.DKIMSignatures) != 1 || !rep.Auth.DKIMSignatures[0].BodyHashMatch {
		t.Fatalf("expected offline DKIM bh= match, got %+v", rep.Auth.DKIMSignatures)
	}

	// Tamper with body -> must trigger AUTH-004 critical finding
	rawTampered := rawGood + "Injected phishing footer\r\n"
	repBad, err := AnalyzeBytes("dkim_tampered.eml", []byte(rawTampered))
	if err != nil {
		t.Fatalf("AnalyzeBytes tampered failed: %v", err)
	}
	if repBad.Auth.DKIMSignatures[0].BodyHashMatch {
		t.Fatalf("expected tampered DKIM body hash mismatch")
	}
	if !hasRule(repBad.Findings, "AUTH-004") {
		t.Fatalf("expected AUTH-004 finding for tampered DKIM body")
	}
}

func TestSanitizeHTMLOfflineBlocksTrackingPixelsAndScripts(t *testing.T) {
	raw := `<html><body><script>alert(1)</script><p onclick="evil()">Hi</p><img src="https://evil-track.xyz/px.gif"><a href="javascript:alert(2)">Click</a></body></html>`
	san, hosts, count := SanitizeHTMLOffline(raw)
	if strings.Contains(strings.ToLower(san), "<script") || strings.Contains(strings.ToLower(san), "onclick=") || strings.Contains(strings.ToLower(san), "javascript:") {
		t.Fatalf("sanitizer left active content behind: %s", san)
	}
	if count != 1 || len(hosts) != 1 || hosts[0] != "evil-track.xyz" {
		t.Fatalf("expected 1 blocked remote host evil-track.xyz, got count=%d hosts=%v", count, hosts)
	}
}

func TestRLOFilenameAndLNKAttachment(t *testing.T) {
	// LNK magic header + UTF-16LE "powershell -enc AAA"
	lnk := []byte{0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00}
	lnk = append(lnk, []byte("powershell.exe -encodedcommand AAAA https://dropper.xyz/p.ps1")...)
	b64 := base64.StdEncoding.EncodeToString(lnk)

	raw := "From: sender@evil.xyz\r\n" +
		"Subject: Document\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"b9\"\r\n" +
		"\r\n" +
		"--b9\r\n" +
		"Content-Type: application/octet-stream; name=\"invoice_\u202efdp.lnk\"\r\n" +
		"Content-Disposition: attachment; filename=\"invoice_\u202efdp.lnk\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" + b64 + "\r\n--b9--\r\n"

	rep, err := AnalyzeBytes("lnk_rlo.eml", []byte(raw))
	if err != nil {
		t.Fatalf("AnalyzeBytes failed: %v", err)
	}
	if !hasRule(rep.Findings, "ATT-001") {
		t.Errorf("expected ATT-001 RLO filename finding")
	}
	if !hasRule(rep.Findings, "ATT-009") {
		t.Errorf("expected ATT-009 LOLBin script indicator in LNK")
	}
	if !hasRule(rep.Findings, "ATT-010") {
		t.Errorf("expected ATT-010 high-risk binary shortcut payload")
	}
	if rep.Score.Verdict != model.VerdictCritical {
		t.Errorf("expected CRITICAL verdict, got %s (%d)", rep.Score.Verdict, rep.Score.Total)
	}
}

func TestAllBuiltInSyntheticSamples(t *testing.T) {
	all := samples.All()
	if len(all) != 4 {
		t.Fatalf("expected 4 built-in samples, got %d", len(all))
	}

	for _, s := range all {
		rep, err := AnalyzeBytes(s.Filename, s.Raw)
		if err != nil {
			t.Fatalf("sample %s failed: %v", s.ID, err)
		}
		switch s.ID {
		case "homoglyph-cred-phish":
			if rep.Score.Verdict != model.VerdictCritical {
				t.Errorf("sample %s: expected CRITICAL, got %s (%d)", s.ID, rep.Score.Verdict, rep.Score.Total)
			}
			for _, rule := range []string{"HDR-004", "HDR-006", "AUTH-004", "HOP-002", "HTML-004", "URL-001", "URL-002"} {
				if !hasRule(rep.Findings, rule) {
					t.Errorf("sample %s missing expected rule %s", s.ID, rule)
				}
			}
		case "html-smuggling-dropper":
			if rep.Score.Verdict != model.VerdictCritical {
				t.Errorf("sample %s: expected CRITICAL, got %s (%d)", s.ID, rep.Score.Verdict, rep.Score.Total)
			}
			for _, rule := range []string{"ATT-002", "ATT-003", "ATT-006", "URL-005"} {
				if !hasRule(rep.Findings, rule) {
					t.Errorf("sample %s missing expected rule %s", s.ID, rule)
				}
			}
		case "bec-macro-invoice":
			if rep.Score.Verdict != model.VerdictCritical {
				t.Errorf("sample %s: expected CRITICAL, got %s (%d)", s.ID, rep.Score.Verdict, rep.Score.Total)
			}
			for _, rule := range []string{"HDR-002", "ATT-004", "ATT-005", "ATT-007"} {
				if !hasRule(rep.Findings, rule) {
					t.Errorf("sample %s missing expected rule %s", s.ID, rule)
				}
			}
		case "clean-authenticated":
			if rep.Score.Verdict != model.VerdictClean || rep.Score.Total != 0 {
				t.Errorf("clean baseline expected CLEAN (0), got %s (%d); findings=%+v", rep.Score.Verdict, rep.Score.Total, rep.Findings)
			}
			if len(rep.Auth.DKIMSignatures) != 1 || !rep.Auth.DKIMSignatures[0].BodyHashMatch {
				t.Errorf("clean baseline expected offline DKIM bh= match")
			}
		}
	}
}

func hasRule(findings []model.Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}
