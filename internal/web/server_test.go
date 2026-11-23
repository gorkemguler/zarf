package web

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorkemguler/zarf/internal/samples"
)

func TestWebAPIAndSecurityHeaders(t *testing.T) {
	srv := NewServer()
	h := srv.Handler()

	// 1. Health & strict CSP check
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'self'") {
		t.Fatalf("missing strict offline CSP header: %q", csp)
	}

	// 2. Inspect built-in sample
	req = httptest.NewRequest(http.MethodPost, "/api/samples/html-smuggling-dropper", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("sample inspect expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var item SessionItem
	if err := json.Unmarshal(rec.Body.Bytes(), &item); err != nil {
		t.Fatalf("decode sample response: %v", err)
	}
	if item.ID == "" || item.Report == nil || item.Report.Score.Total < 75 {
		t.Fatalf("unexpected sample score: %+v", item.Report.Score)
	}

	// 3. Export STIX 2.1 for analyzed item
	req = httptest.NewRequest(http.MethodGet, "/api/export/"+item.ID+"/stix", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"type": "bundle"`) {
		t.Fatalf("STIX export failed: code=%d", rec.Code)
	}

	// 4. Multipart .eml upload
	samp, _ := samples.ByID("clean-authenticated")
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, _ := mw.CreateFormFile("file", samp.Filename)
	_, _ = part.Write(samp.Raw)
	_ = mw.Close()

	req = httptest.NewRequest(http.MethodPost, "/api/analyze", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("multipart analyze expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var cleanItem SessionItem
	_ = json.Unmarshal(rec.Body.Bytes(), &cleanItem)
	if cleanItem.Report.Score.Total != 0 {
		t.Fatalf("expected clean score 0, got %d", cleanItem.Report.Score.Total)
	}

	// 5. Static index.html served cleanly
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "ZARF") {
		t.Fatalf("index.html failed: code=%d", rec.Code)
	}

	// 6. Shutdown endpoint requires X-Zarf-Stop header and configured callback
	stopped := make(chan struct{}, 1)
	srv.SetShutdownFunc(func() { stopped <- struct{}{} })

	req = httptest.NewRequest(http.MethodPost, "/api/shutdown", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without X-Zarf-Stop header, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/shutdown", nil)
	req.Header.Set("X-Zarf-Stop", "1")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with X-Zarf-Stop header, got %d", rec.Code)
	}
	<-stopped
}
