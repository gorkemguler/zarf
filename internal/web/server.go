package web

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gorkemguler/zarf/internal/analyzer"
	"github.com/gorkemguler/zarf/internal/export"
	"github.com/gorkemguler/zarf/internal/model"
	"github.com/gorkemguler/zarf/internal/samples"
)

//go:embed static/*
var staticFS embed.FS

const maxUploadBytes = 25 * 1024 * 1024 // 25 MB per .eml upload

// SessionItem stores an analyzed email in memory for the current local session.
type SessionItem struct {
	ID       string        `json:"id"`
	Filename string        `json:"filename"`
	SampleID string        `json:"sample_id,omitempty"`
	Report   *model.Report `json:"report"`
}

// Server serves the embedded zero-dependency Zarf forensic workbench over localhost.
type Server struct {
	mu         sync.RWMutex
	history    []*SessionItem
	byID       map[string]*SessionItem
	mux        *http.ServeMux
	shutdownFn func()
}

// NewServer initializes the local forensic Web UI & API server.
func NewServer() *Server {
	s := &Server{
		byID: make(map[string]*SessionItem),
		mux:  http.NewServeMux(),
	}
	s.routes()
	return s
}

// SetShutdownFunc enables the optional localhost UI shutdown endpoint (used by desktop launchers).
func (s *Server) SetShutdownFunc(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.shutdownFn = fn
}

// PreloadFile loads an .eml file passed via `zarf serve file.eml` into the session.
func (s *Server) PreloadFile(path string) (*SessionItem, error) {
	rep, err := analyzer.AnalyzeFile(path)
	if err != nil {
		return nil, err
	}
	return s.store(filepath.Base(path), "", rep), nil
}

// Handler returns the HTTP handler wrapped with strict offline security headers.
func (s *Server) Handler() http.Handler {
	return securityHeaders(s.mux)
}

func (s *Server) routes() {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	fileServer := http.FileServer(http.FS(sub))

	s.mux.HandleFunc("/api/health", s.handleHealth)
	s.mux.HandleFunc("/api/shutdown", s.handleShutdown)
	s.mux.HandleFunc("/api/samples", s.handleSamples)
	s.mux.HandleFunc("/api/samples/", s.handleSampleInspect)
	s.mux.HandleFunc("/api/analyze", s.handleAnalyze)
	s.mux.HandleFunc("/api/history", s.handleHistory)
	s.mux.HandleFunc("/api/report/", s.handleReportByID)
	s.mux.HandleFunc("/api/export/", s.handleExport)
	s.mux.Handle("/", fileServer)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Strict offline Content Security Policy: zero external scripts, fonts, images, or XHRs!
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	canStop := s.shutdownFn != nil
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"status":       "ok",
		"tool":         "zarf",
		"version":      model.Version,
		"offline_mode": true,
		"can_stop":     canStop,
	})
}

func (s *Server) handleShutdown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Require custom header (blocked cross-origin because no CORS headers are set).
	if r.Header.Get("X-Zarf-Stop") != "1" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "missing X-Zarf-Stop header"})
		return
	}
	s.mu.RLock()
	fn := s.shutdownFn
	s.mu.RUnlock()
	if fn == nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "ui shutdown disabled"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "stopping"})
	go fn()
}

func (s *Server) handleSamples(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, samples.All())
}

func (s *Server) handleSampleInspect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/samples/")
	id = strings.Trim(id, "/")
	samp, ok := samples.ByID(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "sample not found"})
		return
	}
	rep, err := analyzer.AnalyzeBytes(samp.Filename, samp.Raw)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	item := s.store(samp.Filename, samp.ID, rep)
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)

	var filename string
	var raw []byte
	var err error

	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.HasPrefix(ct, "multipart/form-data") {
		if err = r.ParseMultipartForm(maxUploadBytes); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid multipart upload: " + err.Error()})
			return
		}
		file, hdr, err2 := r.FormFile("file")
		if err2 != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing 'file' form field"})
			return
		}
		defer file.Close()
		filename = hdr.Filename
		raw, err = io.ReadAll(io.LimitReader(file, maxUploadBytes))
	} else {
		filename = r.URL.Query().Get("filename")
		if filename == "" {
			filename = "pasted_email.eml"
		}
		raw, err = io.ReadAll(io.LimitReader(r.Body, maxUploadBytes))
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read email bytes: " + err.Error()})
		return
	}
	if len(raw) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "empty email input"})
		return
	}

	rep, err := analyzer.AnalyzeBytes(filepath.Base(filename), raw)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	item := s.store(filepath.Base(filename), "", rep)
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	type summary struct {
		ID       string        `json:"id"`
		Filename string        `json:"filename"`
		SampleID string        `json:"sample_id,omitempty"`
		Subject  string        `json:"subject"`
		From     string        `json:"from"`
		Score    int           `json:"score"`
		Verdict  model.Verdict `json:"verdict"`
		SHA256   string        `json:"sha256"`
	}
	out := make([]summary, 0, len(s.history))
	for _, it := range s.history {
		from := ""
		if it.Report.Headers.From != nil {
			from = it.Report.Headers.From.Address
		}
		out = append(out, summary{
			ID:       it.ID,
			Filename: it.Filename,
			SampleID: it.SampleID,
			Subject:  it.Report.Headers.Subject,
			From:     from,
			Score:    it.Report.Score.Total,
			Verdict:  it.Report.Score.Verdict,
			SHA256:   it.Report.Evidence.SHA256,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleReportByID(w http.ResponseWriter, r *http.Request) {
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/report/"), "/")
	item, ok := s.get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "report not found"})
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	// Route: /api/export/{id}/{format}?lang=en|tr
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/export/"), "/")
	parts := strings.Split(rest, "/")
	if len(parts) < 2 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expected /api/export/{id}/{format}"})
		return
	}
	id, format := parts[0], strings.ToLower(parts[1])
	item, ok := s.get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "report not found"})
		return
	}
	rep := item.Report
	base := strings.TrimSuffix(item.Filename, filepath.Ext(item.Filename))

	switch format {
	case "json":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.zarf.json"`, safeHeaderFilename(base)))
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	case "md", "markdown":
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.zarf.md"`, safeHeaderFilename(base)))
		_, _ = io.WriteString(w, export.RenderMarkdown(rep))
	case "stix":
		data, err := export.RenderSTIX21(rep)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/stix+json; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.stix21.json"`, safeHeaderFilename(base)))
		_, _ = w.Write(data)
	case "takedown":
		lang := r.URL.Query().Get("lang")
		if lang == "" {
			lang = "en"
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.takedown.%s.txt"`, safeHeaderFilename(base), lang))
		_, _ = io.WriteString(w, export.RenderTakedownDraft(rep, lang))
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported export format: " + format})
	}
}

func (s *Server) store(filename, sampleID string, rep *model.Report) *SessionItem {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Reuse existing session item if identical SHA-256 already analyzed
	for _, existing := range s.history {
		if existing.Report.Evidence.SHA256 == rep.Evidence.SHA256 {
			return existing
		}
	}

	b := make([]byte, 6)
	_, _ = rand.Read(b)
	id := hex.EncodeToString(b)

	item := &SessionItem{
		ID:       id,
		Filename: filename,
		SampleID: sampleID,
		Report:   rep,
	}
	// Prepend so newest appears at top
	s.history = append([]*SessionItem{item}, s.history...)
	if len(s.history) > 50 {
		removed := s.history[len(s.history)-1]
		delete(s.byID, removed.ID)
		s.history = s.history[:len(s.history)-1]
	}
	s.byID[id] = item
	return item
}

func (s *Server) get(id string) (*SessionItem, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	it, ok := s.byID[id]
	return it, ok
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func safeHeaderFilename(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" {
		return "report"
	}
	return out
}
