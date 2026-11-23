package analyzer

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/gorkemguler/zarf/internal/model"
	"github.com/gorkemguler/zarf/internal/parser"
)

var (
	rxFromClause = regexp.MustCompile(`(?i)\bfrom\s+([^\s(]+)(?:\s*\(([^)]*)\))?`)
	rxByClause   = regexp.MustCompile(`(?i)\bby\s+([^\s(;]+)(?:\s*\(([^)]*)\))?`)
	rxWithClause = regexp.MustCompile(`(?i)\bwith\s+([A-Za-z0-9_.\-/]+)`)
	rxTLSClause  = regexp.MustCompile(`(?i)\b(?:version=)?(TLSv?1(?:\.[0-3])?)\b(?:\s+cipher=([^\s;)]+))?`)
	rxIPv4       = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
	rxIPv6       = regexp.MustCompile(`(?i)\b(?:IPv6:)?([0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7})\b`)
)

// AnalyzeHops reconstructs the chronological SMTP relay path from Received headers
// and detects clock skew, suspicious transit delays, unencrypted hops, and origin IPs.
func AnalyzeHops(pe *parser.ParsedEmail) (model.HopChain, []model.Finding) {
	var rawReceived []string
	for _, h := range pe.Headers {
		if strings.EqualFold(h.Name, "Received") {
			rawReceived = append(rawReceived, h.Value)
		}
	}

	var chain model.HopChain
	var findings []model.Finding
	seenPublicIP := map[string]bool{}

	// Received headers are prepended by each relay (top = newest, bottom = earliest).
	// Reverse them so Hop 1 is the earliest observed hop (origin).
	n := len(rawReceived)
	hops := make([]model.Hop, 0, n)
	for i := n - 1; i >= 0; i-- {
		hop := parseReceivedHeader(rawReceived[i], len(hops)+1)
		hops = append(hops, hop)
	}

	// Calculate hop-to-hop deltas and anomalies
	for i := range hops {
		if hops[i].FromIP != "" && hops[i].IPScope == "public" {
			if !seenPublicIP[hops[i].FromIP] {
				seenPublicIP[hops[i].FromIP] = true
				chain.PublicIPs = append(chain.PublicIPs, hops[i].FromIP)
			}
			if chain.OriginIP == "" {
				chain.OriginIP = hops[i].FromIP
				chain.OriginHost = hops[i].FromHost
			}
		}
		if i > 0 && hops[i].Timestamp != nil && hops[i-1].Timestamp != nil {
			delta := hops[i].Timestamp.Sub(*hops[i-1].Timestamp).Seconds()
			hops[i].DelaySeconds = &delta
			if delta < -60 {
				hops[i].ClockSkew = true
				chain.HasClockSkew = true
				hops[i].Notes = append(hops[i].Notes, fmt.Sprintf("Negative time jump of %.0fs vs previous hop", delta))
			} else if delta > 600 {
				hops[i].DelayAnomaly = true
				hops[i].Notes = append(hops[i].Notes, fmt.Sprintf("Delayed %.0fs before next relay", delta))
			}
		}

		// Detect unencrypted external SMTP transport
		protoUp := strings.ToUpper(hops[i].Protocol)
		if !hops[i].TLS && hops[i].IPScope == "public" && (protoUp == "SMTP" || protoUp == "ESMTP" || protoUp == "ESMTPA") {
			chain.HasUnencryptedHop = true
			hops[i].Notes = append(hops[i].Notes, "Plaintext SMTP hop over public IP (no TLS)")
		}
	}

	// Also inspect X-Originating-IP as a secondary origin hint
	if xip := strings.Trim(strings.TrimSpace(pe.HeaderMap.Get("X-Originating-Ip")), "[] "); xip != "" {
		if ip := extractFirstIP(xip); ip != "" {
			if classifyIP(ip) == "public" {
				if !seenPublicIP[ip] {
					seenPublicIP[ip] = true
					chain.PublicIPs = append([]string{ip}, chain.PublicIPs...)
				}
				if chain.OriginIP == "" {
					chain.OriginIP = ip
				}
			}
		}
	}

	if len(hops) > 0 {
		chain.FinalHost = hops[len(hops)-1].ByHost
		if chain.OriginHost == "" {
			chain.OriginHost = hops[0].FromHost
		}
		if hops[0].Timestamp != nil && hops[len(hops)-1].Timestamp != nil {
			tot := hops[len(hops)-1].Timestamp.Sub(*hops[0].Timestamp).Seconds()
			chain.TotalTransitSec = &tot
		}
	}
	chain.Hops = hops

	if len(hops) == 0 {
		findings = append(findings, model.Finding{
			RuleID:      "HOP-001",
			Category:    "hops",
			Severity:    model.SeverityMedium,
			Points:      8,
			Title:       "No Received relay headers present",
			Description: "The email has no SMTP Received hop trail, which may indicate a locally forged .eml artifact or stripped headers.",
		})
	}
	if chain.HasClockSkew {
		findings = append(findings, model.Finding{
			RuleID:      "HOP-002",
			Category:    "hops",
			Severity:    model.SeverityMedium,
			Points:      10,
			Title:       "Negative timestamp jump in Received hop chain",
			Description: "A downstream mail server recorded an earlier timestamp than an upstream hop (>60s skew). This can indicate forged Received headers or misconfigured rogue relays.",
		})
	}
	if chain.HasUnencryptedHop {
		findings = append(findings, model.Finding{
			RuleID:      "HOP-003",
			Category:    "hops",
			Severity:    model.SeverityLow,
			Points:      5,
			Title:       "Unencrypted SMTP hop over public network",
			Description: "At least one external mail relay transmitted the message without TLS (ESMTPS).",
		})
	}

	// Check Date header vs first/last Received timestamp drift (> 24h)
	if dateRaw := strings.TrimSpace(pe.HeaderMap.Get("Date")); dateRaw != "" && len(hops) > 0 {
		if headerDate, err := parseEmailDate(dateRaw); err == nil {
			var refTime = hops[len(hops)-1].Timestamp
			if refTime != nil {
				diff := refTime.Sub(headerDate).Hours()
				if diff > 24 || diff < -24 {
					findings = append(findings, model.Finding{
						RuleID:      "HOP-004",
						Category:    "hops",
						Severity:    model.SeverityMedium,
						Points:      8,
						Title:       "Date header diverges significantly from delivery timestamp",
						Description: "The declared Date header differs by more than 24 hours from the receiving server timestamp, a technique sometimes used to manipulate inbox sorting or forge backdated threads.",
						Evidence:    fmt.Sprintf("Date=%s | FinalHop=%s (drift %.1fh)", headerDate.UTC().Format("2006-01-02 15:04Z"), refTime.UTC().Format("2006-01-02 15:04Z"), diff),
					})
				}
			}
		}
	}

	return chain, findings
}

func parseReceivedHeader(raw string, index int) model.Hop {
	hop := model.Hop{
		Index:   index,
		Raw:     raw,
		IPScope: "unknown",
	}

	// Split timestamp after last semicolon
	body := raw
	if semi := strings.LastIndexByte(raw, ';'); semi >= 0 {
		body = strings.TrimSpace(raw[:semi])
		hop.TimestampRaw = strings.TrimSpace(raw[semi+1:])
		if t, err := parseEmailDate(hop.TimestampRaw); err == nil {
			hop.Timestamp = &t
		}
	}

	if m := rxFromClause.FindStringSubmatch(body); len(m) >= 2 {
		hop.FromHost = strings.Trim(m[1], "[]()")
		// Prefer IP inside parenthesized rDNS/bracket block, otherwise FromHost itself
		if len(m) >= 3 && m[2] != "" {
			if ip := extractFirstIP(m[2]); ip != "" {
				hop.FromIP = ip
			}
		}
		if hop.FromIP == "" {
			if ip := extractFirstIP(hop.FromHost); ip != "" {
				hop.FromIP = ip
			}
		}
	}
	if hop.FromIP != "" {
		hop.IPScope = classifyIP(hop.FromIP)
	}

	if m := rxByClause.FindStringSubmatch(body); len(m) >= 2 {
		hop.ByHost = strings.Trim(m[1], "[]()")
		if len(m) >= 3 && m[2] != "" {
			hop.ByIP = extractFirstIP(m[2])
		}
	}

	if m := rxWithClause.FindStringSubmatch(body); len(m) >= 2 {
		hop.Protocol = m[1]
	}

	low := strings.ToLower(body)
	protoUp := strings.ToUpper(hop.Protocol)
	if strings.Contains(protoUp, "ESMTPS") || strings.Contains(protoUp, "HTTPS") ||
		strings.Contains(low, "tls") || strings.Contains(low, "ssl") || strings.Contains(low, "cipher=") {
		hop.TLS = true
	}
	if m := rxTLSClause.FindStringSubmatch(body); len(m) >= 2 {
		hop.TLS = true
		if len(m) >= 3 && m[2] != "" {
			hop.Cipher = m[1] + " / " + m[2]
		} else {
			hop.Cipher = m[1]
		}
	}

	return hop
}

func extractFirstIP(s string) string {
	if m := rxIPv4.FindString(s); m != "" {
		if _, err := netip.ParseAddr(m); err == nil {
			return m
		}
	}
	if m := rxIPv6.FindStringSubmatch(s); len(m) >= 2 {
		cand := strings.Trim(m[1], "[]")
		if addr, err := netip.ParseAddr(cand); err == nil && addr.Is6() {
			return addr.String()
		}
	}
	return ""
}

func classifyIP(ipStr string) string {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return "unknown"
	}
	switch {
	case addr.IsLoopback():
		return "loopback"
	case addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified():
		return "private"
	default:
		return "public"
	}
}
