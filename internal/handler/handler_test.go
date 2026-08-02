package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ecosyste-ms/licenses/internal/archive"
	"github.com/ecosyste-ms/licenses/internal/scanner"
)

type fakeScanner struct {
	report scanner.Report
	err    error
	call   func(context.Context)
}

func (f *fakeScanner) ScanURL(ctx context.Context, _ string) (scanner.Report, error) {
	if f.call != nil {
		f.call(ctx)
	}
	return f.report, f.err
}

func TestLicensesSuccess(t *testing.T) {
	t.Parallel()
	service := &fakeScanner{report: testReport()}
	handler := newTestHandler(t, service, time.Second)
	request := httptest.NewRequest(http.MethodGet, "/api/v2/licenses?url=https://example.test/package.zip", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("X-Archive-SHA256"); got != service.report.SHA256 {
		t.Fatalf("X-Archive-SHA256 = %q", got)
	}
	if got := response.Header().Get("Cache-Control"); !strings.Contains(got, "public") {
		t.Fatalf("Cache-Control = %q", got)
	}
	if got := response.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("CORS header = %q", got)
	}
	var decoded scanner.Report
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Schema != 1 || decoded.Files == nil || decoded.Errors == nil {
		t.Fatalf("decoded report = %#v", decoded)
	}
}

func TestLicensesValidationAndErrorMapping(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		path   string
		err    error
		status int
	}{
		{name: "missing URL", path: "/api/v2/licenses", status: http.StatusBadRequest},
		{
			name: "invalid", path: "/api/v2/licenses?url=bad",
			err:    &archive.Error{Kind: archive.KindInvalid, Op: "validate", Err: errors.New("bad URL")},
			status: http.StatusBadRequest,
		},
		{
			name: "limit", path: "/api/v2/licenses?url=https://example.test/archive",
			err:    &archive.Error{Kind: archive.KindLimit, Op: "extract", Err: errors.New("too large")},
			status: http.StatusRequestEntityTooLarge,
		},
		{
			name: "download", path: "/api/v2/licenses?url=https://example.test/archive",
			err:    &archive.Error{Kind: archive.KindDownload, Op: "download", Err: errors.New("offline")},
			status: http.StatusBadGateway,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &fakeScanner{report: testReport(), err: test.err}
			handler := newTestHandler(t, service, time.Second)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.path, nil))
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, test.status, response.Body.String())
			}
		})
	}
}

func TestLicensesSemaphoreTimeout(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var calls atomic.Int32
	service := &fakeScanner{report: testReport(), call: func(ctx context.Context) {
		calls.Add(1)
		entered <- struct{}{}
		<-release
	}}
	openAPIPath := writeSpec(t)
	handler, err := New(service, 1, 30*time.Millisecond, openAPIPath)
	if err != nil {
		t.Fatal(err)
	}
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v2/licenses?url=https://example.test/one", nil))
	}()
	<-entered
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v2/licenses?url=https://example.test/two", nil))
	if response.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if calls.Load() != 1 {
		t.Fatalf("scanner calls = %d, want 1", calls.Load())
	}
	close(release)
	<-firstDone
}

func TestSupportingRoutes(t *testing.T) {
	t.Parallel()
	handler := newTestHandler(t, &fakeScanner{report: testReport()}, time.Second)
	tests := []struct {
		path        string
		status      int
		contentType string
	}{
		{path: "/", status: 200, contentType: "text/html"},
		{path: "/healthz", status: 200, contentType: "application/json"},
		{path: "/docs/", status: 200, contentType: "text/html"},
		{path: "/docs/api/v2/openapi.yaml", status: 200, contentType: "application/yaml"},
		{path: "/missing", status: 404, contentType: "application/json"},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.path, nil))
			if response.Code != test.status {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			if got := response.Header().Get("Content-Type"); !strings.Contains(got, test.contentType) {
				t.Fatalf("Content-Type = %q", got)
			}
		})
	}
}

func TestUnsupportedMethod(t *testing.T) {
	t.Parallel()
	handler := newTestHandler(t, &fakeScanner{report: testReport()}, time.Second)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v2/licenses", nil))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d", response.Code)
	}
}

func TestOptions(t *testing.T) {
	t.Parallel()
	handler := newTestHandler(t, &fakeScanner{report: testReport()}, time.Second)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodOptions, "/api/v2/licenses", nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d", response.Code)
	}
	if got := response.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(got, "GET") {
		t.Fatalf("Access-Control-Allow-Methods = %q", got)
	}
}

func BenchmarkHandleLicenses(b *testing.B) {
	handler, err := New(&fakeScanner{report: testReport()}, 4, time.Second, "unused")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/api/v2/licenses?url=https://example.test/package.zip", nil)
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				b.Fatalf("status = %d", response.Code)
			}
		}
	})
}

func newTestHandler(t *testing.T, service ScanService, timeout time.Duration) *Server {
	t.Helper()
	handler, err := New(service, 2, timeout, writeSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func writeSpec(t *testing.T) string {
	t.Helper()
	filePath := filepath.Join(t.TempDir(), "openapi.yaml")
	if err := os.WriteFile(filePath, []byte("openapi: 3.0.3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return filePath
}

func testReport() scanner.Report {
	return scanner.Report{
		Schema: 1, URL: "https://example.test/package.zip",
		SHA256: strings.Repeat("a", 64),
		Scanner: scanner.ScannerInfo{
			Name: scanner.ScannerName, Version: scanner.ScannerVersion,
			Corpus: scanner.CorpusInfo{Version: "test", SourceCommit: strings.Repeat("b", 40), RuleCount: 1},
		},
		Summary: scanner.Summary{
			Complete: true, RootExpressions: []scanner.Expression{}, OtherExpressions: []scanner.Expression{},
		},
		Declared: []scanner.DeclaredLicense{}, Files: []scanner.File{},
		AttributionFiles: []scanner.AttributionFile{}, Skipped: []scanner.Skip{}, Errors: []scanner.ScanError{},
	}
}
