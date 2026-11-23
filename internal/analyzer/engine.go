package analyzer

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gorkemguler/zarf/internal/model"
	"github.com/gorkemguler/zarf/internal/parser"
)

const maxNestedEMLDepth = 3

// AnalyzeBytes executes the complete 100% offline forensic pipeline on raw .eml bytes.
func AnalyzeBytes(filename string, raw []byte) (*model.Report, error) {
	return analyzeWithDepth(filename, raw, 0)
}

// AnalyzeFile reads an .eml file from disk and performs offline autopsy.
func AnalyzeFile(path string) (*model.Report, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return AnalyzeBytes(filepath.Base(path), raw)
}

func analyzeWithDepth(filename string, raw []byte, depth int) (*model.Report, error) {
	pe, err := parser.ParseEML(filename, raw)
	if err != nil {
		return nil, err
	}

	var allFindings []model.Finding

	// 1. Auth & offline DKIM bh= verification
	auth, authFindings := AnalyzeAuth(pe)
	allFindings = append(allFindings, authFindings...)

	// 2. Headers & identity spoofing
	headers, identity, hdrFindings := AnalyzeHeaders(pe, &auth)
	allFindings = append(allFindings, hdrFindings...)

	// 3. SMTP Received hop chain
	hops, hopFindings := AnalyzeHops(pe)
	allFindings = append(allFindings, hopFindings...)

	// 4. Body, HTML smuggling, CSS cloaking, stealth Unicode & offline safe preview
	body, bodyFindings := AnalyzeBody(pe)
	allFindings = append(allFindings, bodyFindings...)

	// 5. Static attachment forensics (ZIP/OOXML, OLE2, PDF, LNK, HTML/SVG, magic mismatch)
	attachments, attURLs, attFindings := AnalyzeAttachments(pe)
	allFindings = append(allFindings, attFindings...)

	// 6. URL, Punycode/homoglyph, anchor-mismatch & brand lookalike analysis
	urls, urlFindings := AnalyzeURLs(pe, body, attURLs, identity.FromDomain)
	allFindings = append(allFindings, urlFindings...)

	// 7. Recursive autopsy for nested message/rfc822 emails
	var nested []*model.Report
	if depth < maxNestedEMLDepth {
		for i, nRaw := range pe.NestedEMLs {
			nName := fmt.Sprintf("nested_%d.eml", i+1)
			if nr, err := analyzeWithDepth(nName, nRaw, depth+1); err == nil {
				nested = append(nested, nr)
				if nr.Score.Total >= 50 {
					allFindings = append(allFindings, model.Finding{
						RuleID:      "EML-001",
						Category:    "attachments",
						Severity:    model.SeverityHigh,
						Points:      20,
						Title:       fmt.Sprintf("Attached nested .eml scored %d/100 (%s)", nr.Score.Total, nr.Score.Verdict),
						Description: "An attached message/rfc822 email contains high-risk phishing or payload indicators.",
						Evidence:    fmt.Sprintf("Subject=%q Score=%d", nr.Headers.Subject, nr.Score.Total),
					})
				}
			}
		}
	}

	SortFindings(allFindings)
	score := ComputeRiskScore(allFindings)

	rep := &model.Report{
		ToolVersion:   model.Version,
		AnalyzedAt:    time.Now().UTC(),
		OfflineMode:   true,
		Evidence:      pe.Evidence,
		Score:         score,
		Headers:       headers,
		Identity:      identity,
		Hops:          hops,
		Auth:          auth,
		Body:          body,
		URLs:          urls,
		Attachments:   attachments,
		Findings:      allFindings,
		NestedReports: nested,
	}
	rep.IOCs = ExtractIOCs(rep)
	rep.Recommendations = BuildRecommendations(rep)
	return rep, nil
}

// AnalyzeBatch scans a directory (recursively) for .eml / .msg-text files and builds a triage summary.
func AnalyzeBatch(dir string) (*model.BatchSummary, error) {
	summary := &model.BatchSummary{
		ScannedAt: time.Now().UTC(),
		Directory: dir,
	}

	var files []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext == ".eml" || ext == ".rfc822" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)

	for _, f := range files {
		rel, _ := filepath.Rel(dir, f)
		if rel == "" {
			rel = filepath.Base(f)
		}
		rep, err := AnalyzeFile(f)
		if err != nil {
			summary.Items = append(summary.Items, model.BatchEntry{
				Filename: rel,
				Error:    err.Error(),
			})
			continue
		}
		fromStr := ""
		if rep.Headers.From != nil {
			fromStr = rep.Headers.From.Address
		}
		var tops []string
		for i := 0; i < len(rep.Findings) && i < 3; i++ {
			tops = append(tops, fmt.Sprintf("[%s] %s", rep.Findings[i].RuleID, rep.Findings[i].Title))
		}
		summary.Items = append(summary.Items, model.BatchEntry{
			Filename:    rel,
			SHA256:      rep.Evidence.SHA256,
			From:        fromStr,
			Subject:     rep.Headers.Subject,
			Score:       rep.Score.Total,
			Verdict:     rep.Score.Verdict,
			TopFindings: tops,
		})
		summary.Total++
		switch rep.Score.Verdict {
		case model.VerdictCritical:
			summary.Critical++
		case model.VerdictHigh:
			summary.High++
		case model.VerdictMedium:
			summary.Medium++
		case model.VerdictLow:
			summary.Low++
		default:
			summary.Clean++
		}
	}

	// Sort highest risk first for immediate SOC triage
	sort.SliceStable(summary.Items, func(i, j int) bool {
		return summary.Items[i].Score > summary.Items[j].Score
	})

	return summary, nil
}
