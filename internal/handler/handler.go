package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/ecosyste-ms/licenses/internal/archive"
	"github.com/ecosyste-ms/licenses/internal/scanner"
)

const successCacheDuration = 24 * time.Hour

// ScanService is implemented by scanner.Scanner and kept narrow for handler
// tests.
type ScanService interface {
	ScanURL(context.Context, string) (scanner.Report, error)
}

// Server exposes the synchronous v2 API and supporting pages.
type Server struct {
	service     ScanService
	semaphore   chan struct{}
	timeout     time.Duration
	openAPIPath string
	mux         *http.ServeMux
}

// New returns a fully configured HTTP handler.
func New(service ScanService, maxConcurrent int, timeout time.Duration, openAPIPath string) (*Server, error) {
	if service == nil {
		return nil, errors.New("scan service is required")
	}
	if maxConcurrent <= 0 {
		return nil, errors.New("maximum concurrency must be positive")
	}
	if timeout <= 0 {
		return nil, errors.New("request timeout must be positive")
	}
	server := &Server{
		service: service, semaphore: make(chan struct{}, maxConcurrent),
		timeout: timeout, openAPIPath: openAPIPath, mux: http.NewServeMux(),
	}
	server.routes()
	return server, nil
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/v2/licenses", s.handleLicenses)
	s.mux.HandleFunc("OPTIONS /api/v2/licenses", handleOptions)
	s.mux.HandleFunc("GET /docs", redirectDocs)
	s.mux.HandleFunc("GET /docs/", handleDocs)
	s.mux.HandleFunc("GET /docs/api/v2/openapi.yaml", s.handleOpenAPI)
	s.mux.HandleFunc("GET /healthz", handleHealth)
	s.mux.HandleFunc("GET /", handleHome)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if len(r.URL.Path) >= len("/api/") && r.URL.Path[:len("/api/")] == "/api/" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type")
	}
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handleLicenses(w http.ResponseWriter, r *http.Request) {
	rawURL := r.URL.Query().Get("url")
	if rawURL == "" {
		writeError(w, http.StatusBadRequest, "url parameter is required")
		return
	}
	if len(rawURL) > 8<<10 {
		writeError(w, http.StatusBadRequest, "url parameter is too long")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.timeout)
	defer cancel()
	select {
	case s.semaphore <- struct{}{}:
		defer func() { <-s.semaphore }()
	case <-ctx.Done():
		writeError(w, http.StatusGatewayTimeout, "scan timed out while waiting for capacity")
		return
	}

	report, err := s.service.ScanURL(ctx, rawURL)
	if err != nil {
		status, message := responseError(err)
		if status >= 500 {
			slog.Error("v2 license scan failed", "error", err, "url", rawURL)
		}
		writeError(w, status, message)
		return
	}
	w.Header().Set("Cache-Control", fmt.Sprintf(
		"public, max-age=%d, s-maxage=%d", int(successCacheDuration.Seconds()), int(successCacheDuration.Seconds()),
	))
	w.Header().Set("ETag", fmt.Sprintf(`"%s-%s-%d"`, report.SHA256, report.Scanner.Version, report.Schema))
	w.Header().Set("X-Archive-SHA256", report.SHA256)
	writeJSON(w, http.StatusOK, report)
}

func responseError(err error) (int, string) {
	if errors.Is(err, context.DeadlineExceeded) {
		return http.StatusGatewayTimeout, "scan timed out"
	}
	if errors.Is(err, context.Canceled) {
		return http.StatusRequestTimeout, "scan canceled"
	}
	switch archive.KindOf(err) {
	case archive.KindInvalid, archive.KindUnsupported:
		return http.StatusBadRequest, err.Error()
	case archive.KindLimit:
		return http.StatusRequestEntityTooLarge, err.Error()
	case archive.KindDownload:
		return http.StatusBadGateway, "archive download failed"
	case archive.KindExtract:
		return http.StatusInternalServerError, "archive extraction failed"
	default:
		return http.StatusInternalServerError, "license scan failed"
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		slog.Error("encode JSON response", "error", err)
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleOptions(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(homeHTML))
}

func redirectDocs(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/docs/", http.StatusMovedPermanently)
}

func handleDocs(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(docsHTML))
}

func (s *Server) handleOpenAPI(w http.ResponseWriter, _ *http.Request) {
	data, err := os.ReadFile(s.openAPIPath)
	if err != nil {
		writeError(w, http.StatusNotFound, "OpenAPI specification not found")
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	_, _ = w.Write(data)
}

const homeHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Ecosyste.ms: Licenses v2</title><style>body{font:18px system-ui;max-width:52rem;margin:4rem auto;padding:0 1rem;line-height:1.55}code{background:#f3f3f3;padding:.15rem .3rem}</style></head>
<body><h1>Ecosyste.ms: Licenses v2</h1><p>A bounded synchronous API for license evidence in package archives.</p>
<p><code>GET /api/v2/licenses?url=https://example.test/package.tar.gz</code></p><p><a href="/docs/">API documentation</a></p></body></html>`

const docsHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Licenses v2 API documentation</title>
<link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css"></head><body><div id="swagger-ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script><script>SwaggerUIBundle({url:"/docs/api/v2/openapi.yaml",dom_id:"#swagger-ui",deepLinking:true,presets:[SwaggerUIBundle.presets.apis],layout:"BaseLayout"})</script></body></html>`
