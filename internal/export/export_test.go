package export

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/gorkemguler/zarf/internal/analyzer"
	"github.com/gorkemguler/zarf/internal/samples"
)

func TestExportersProduceValidOutputs(t *testing.T) {
	samp, ok := samples.ByID("homoglyph-cred-phish")
	if !ok {
		t.Fatal("sample not found")
	}
	rep, err := analyzer.AnalyzeBytes(samp.Filename, samp.Raw)
	if err != nil {
		t.Fatalf("AnalyzeBytes: %v", err)
	}

	// 1. Terminal report
	term := RenderTerminal(rep, false)
	if !strings.Contains(term, "PHISHING RISK SCORE") || !strings.Contains(term, "CRITICAL") || !strings.Contains(term, "hxxps://") {
		t.Errorf("terminal report missing expected sections")
	}

	// 2. Markdown report
	md := RenderMarkdown(rep)
	if !strings.Contains(md, "# Zarf Email Forensic Autopsy Report") || !strings.Contains(md, "## Evidence Integrity Manifest") {
		t.Errorf("markdown report missing headers")
	}

	// 3. STIX 2.1 Bundle
	stixBytes, err := RenderSTIX21(rep)
	if err != nil {
		t.Fatalf("RenderSTIX21 failed: %v", err)
	}
	var bundle map[string]any
	if err := json.Unmarshal(stixBytes, &bundle); err != nil {
		t.Fatalf("invalid STIX JSON: %v", err)
	}
	if bundle["type"] != "bundle" {
		t.Errorf("expected STIX bundle type, got %v", bundle["type"])
	}
	objs, ok := bundle["objects"].([]any)
	if !ok || len(objs) < 5 {
		t.Errorf("expected >= 5 STIX objects, got %d", len(objs))
	}

	// 4. Takedown drafts EN & TR
	tdEN := RenderTakedownDraft(rep, "en")
	if !strings.Contains(tdEN, "Takedown Request") || !strings.Contains(tdEN, "[.]") {
		t.Errorf("EN takedown draft missing expected fields")
	}
	tdTR := RenderTakedownDraft(rep, "tr")
	if !strings.Contains(tdTR, "Oltalama (Phishing)") || !strings.Contains(tdTR, "[.]") {
		t.Errorf("TR takedown draft missing expected fields")
	}
}
