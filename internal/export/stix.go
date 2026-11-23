package export

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/gorkemguler/zarf/internal/model"
)

// RenderSTIX21 builds a standards-compliant STIX 2.1 JSON bundle containing
// email-message, ipv4/ipv6-addr, domain-name, url, file, indicator, and report objects.
func RenderSTIX21(rep *model.Report) ([]byte, error) {
	ts := rep.AnalyzedAt.UTC().Format(time.RFC3339)
	objects := []map[string]any{}
	objectRefs := []string{}

	addObj := func(obj map[string]any) string {
		id := obj["id"].(string)
		objects = append(objects, obj)
		objectRefs = append(objectRefs, id)
		return id
	}

	// 1. Identity for Zarf tool
	identityID := stixID("identity", "zarf-offline-email-forensics")
	objects = append(objects, map[string]any{
		"type":           "identity",
		"spec_version":   "2.1",
		"id":             identityID,
		"created":        ts,
		"modified":       ts,
		"name":           "Zarf Offline Email Forensics",
		"identity_class": "system",
	})

	// 2. Email Address & Email Message SCOs
	var fromRef string
	if rep.Headers.From != nil && rep.Headers.From.Address != "" {
		fromRef = addObj(map[string]any{
			"type":         "email-addr",
			"spec_version": "2.1",
			"id":           stixID("email-addr", strings.ToLower(rep.Headers.From.Address)),
			"value":        strings.ToLower(rep.Headers.From.Address),
			"display_name": rep.Headers.From.DisplayName,
		})
	}

	emailObj := map[string]any{
		"type":         "email-message",
		"spec_version": "2.1",
		"id":           stixID("email-message", rep.Evidence.SHA256),
		"is_multipart": rep.Body.MIMEPieces > 1,
		"subject":      rep.Headers.Subject,
		"message_id":   rep.Headers.MessageID,
	}
	if fromRef != "" {
		emailObj["from_ref"] = fromRef
	}
	if rep.Headers.ParsedDate != nil {
		emailObj["date"] = rep.Headers.ParsedDate.UTC().Format(time.RFC3339)
	}
	addObj(emailObj)

	// 3. IPs
	for _, ip := range rep.IOCs.IPs {
		scoType := "ipv4-addr"
		if addr, err := netip.ParseAddr(ip); err == nil && addr.Is6() {
			scoType = "ipv6-addr"
		}
		addObj(map[string]any{
			"type":         scoType,
			"spec_version": "2.1",
			"id":           stixID(scoType, ip),
			"value":        ip,
		})
	}

	// 4. Domains
	for _, dom := range rep.IOCs.Domains {
		addObj(map[string]any{
			"type":         "domain-name",
			"spec_version": "2.1",
			"id":           stixID("domain-name", dom),
			"value":        dom,
		})
	}

	// 5. URLs & suspicious URL Indicators
	for _, u := range rep.URLs {
		addObj(map[string]any{
			"type":         "url",
			"spec_version": "2.1",
			"id":           stixID("url", u.Raw),
			"value":        u.Raw,
		})
		if u.RiskScore >= 35 {
			addObj(map[string]any{
				"type":            "indicator",
				"spec_version":    "2.1",
				"id":              stixID("indicator", "url:"+u.Raw),
				"created":         ts,
				"modified":        ts,
				"created_by_ref":  identityID,
				"name":            fmt.Sprintf("Suspicious Phishing URL (%s)", u.Host),
				"description":     strings.Join(u.Reasons, "; "),
				"indicator_types": []string{"malicious-activity"},
				"pattern_type":    "stix",
				"pattern":         fmt.Sprintf("[url:value = '%s']", escapeSTIX(u.Raw)),
				"valid_from":      ts,
				"confidence":      u.RiskScore,
			})
		}
	}

	// 6. Attachments as File SCOs + Indicators for high-risk files
	for _, a := range rep.Attachments {
		addObj(map[string]any{
			"type":         "file",
			"spec_version": "2.1",
			"id":           stixID("file", a.SHA256),
			"name":         a.Filename,
			"size":         a.SizeBytes,
			"mime_type":    a.ContentType,
			"hashes": map[string]string{
				"SHA-256": a.SHA256,
				"SHA-1":   a.SHA1,
				"MD5":     a.MD5,
			},
		})
		if a.RiskScore >= 35 {
			addObj(map[string]any{
				"type":            "indicator",
				"spec_version":    "2.1",
				"id":              stixID("indicator", "file:"+a.SHA256),
				"created":         ts,
				"modified":        ts,
				"created_by_ref":  identityID,
				"name":            fmt.Sprintf("Malicious Attachment (%s)", a.Filename),
				"description":     strings.Join(a.Reasons, "; "),
				"indicator_types": []string{"malicious-activity"},
				"pattern_type":    "stix",
				"pattern":         fmt.Sprintf("[file:hashes.'SHA-256' = '%s']", a.SHA256),
				"valid_from":      ts,
				"confidence":      a.RiskScore,
			})
		}
	}

	// 7. Report SDO tying all observables and indicators together
	objects = append(objects, map[string]any{
		"type":           "report",
		"spec_version":   "2.1",
		"id":             stixID("report", rep.Evidence.SHA256),
		"created":        ts,
		"modified":       ts,
		"created_by_ref": identityID,
		"name":           fmt.Sprintf("Zarf Autopsy: %s (%s %d/100)", rep.Evidence.Filename, rep.Score.Verdict, rep.Score.Total),
		"description":    rep.Score.Summary,
		"report_types":   []string{"threat-report", "indicator"},
		"published":      ts,
		"object_refs":    objectRefs,
	})

	bundle := map[string]any{
		"type":    "bundle",
		"id":      stixID("bundle", rep.Evidence.SHA256),
		"objects": objects,
	}
	return json.MarshalIndent(bundle, "", "  ")
}

// stixID produces a deterministic RFC 4122-formatted UUID from SHA-256 of (type + seed).
func stixID(objType, seed string) string {
	sum := sha256.Sum256([]byte("zarf-stix21:" + objType + ":" + seed))
	// Set UUID version 5 bits and variant bits
	sum[6] = (sum[6] & 0x0f) | 0x50
	sum[8] = (sum[8] & 0x3f) | 0x80
	return fmt.Sprintf("%s--%x-%x-%x-%x-%x",
		objType, sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}

func escapeSTIX(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "'", "\\'")
	return s
}
