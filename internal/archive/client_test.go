package archive

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIsPublicIP(t *testing.T) {
	t.Parallel()
	tests := []struct {
		address string
		want    bool
	}{
		{address: "8.8.8.8", want: true},
		{address: "2606:4700:4700::1111", want: true},
		{address: "127.0.0.1", want: false},
		{address: "10.1.2.3", want: false},
		{address: "169.254.169.254", want: false},
		{address: "100.64.0.1", want: false},
		{address: "::1", want: false},
		{address: "fe80::1", want: false},
		{address: "ff02::1", want: false},
	}
	for _, test := range tests {
		t.Run(test.address, func(t *testing.T) {
			if got := IsPublicIP(netip.MustParseAddr(test.address)); got != test.want {
				t.Fatalf("IsPublicIP(%s) = %v, want %v", test.address, got, test.want)
			}
		})
	}
}

func TestValidateURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		raw  string
		want bool
	}{
		{raw: "https://example.com/package.tgz", want: true},
		{raw: "ftp://example.com/package.tgz"},
		{raw: "https:///package.tgz"},
		{raw: "https://user:pass@example.com/package.tgz"},
		{raw: "http://127.0.0.1/package.tgz"},
		{raw: "http://[::1]/package.tgz"},
		{raw: "http://example.com:0/package.tgz"},
	}
	for _, test := range tests {
		t.Run(test.raw, func(t *testing.T) {
			parsed, err := url.Parse(test.raw)
			if err != nil {
				t.Fatal(err)
			}
			if got := ValidateURL(parsed) == nil; got != test.want {
				t.Fatalf("ValidateURL(%q) success = %v, want %v", test.raw, got, test.want)
			}
		})
	}
}

func TestSafeClientRejectsPrivateRedirect(t *testing.T) {
	t.Parallel()
	client := NewSafeHTTPClient(DefaultDownloadLimits())
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/archive.zip", nil)
	if err := client.CheckRedirect(request, []*http.Request{{}}); err == nil {
		t.Fatal("private redirect was accepted")
	}
}

func TestValidatedDialRejectsMixedDNSAnswersBeforeConnecting(t *testing.T) {
	t.Parallel()
	lookup := func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{
			netip.MustParseAddr("8.8.8.8"),
			netip.MustParseAddr("127.0.0.1"),
		}, nil
	}
	called := false
	dial := func(context.Context, string, string) (net.Conn, error) {
		called = true
		return nil, nil
	}
	_, err := validatedDialContext(lookup, dial)(context.Background(), "tcp", "rebinding.test:443")
	if err == nil {
		t.Fatal("mixed public/private DNS response was accepted")
	}
	if called {
		t.Fatal("dial was attempted before every DNS answer was validated")
	}
}

func TestDownload(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("User-Agent"); got != userAgent {
			t.Errorf("User-Agent = %q, want %q", got, userAgent)
		}
		_, _ = io.WriteString(w, "archive bytes")
	}))
	defer server.Close()
	limits := DefaultDownloadLimits()
	client := &Client{
		HTTPClient: server.Client(), Limits: limits, AllowPrivateHosts: true,
	}
	destination := filepath.Join(t.TempDir(), "archive")
	digest, err := client.Download(context.Background(), server.URL, destination)
	if err != nil {
		t.Fatal(err)
	}
	if digest != "cc9c340301ad4ba5e54aa24b442ff938d1ed84f7f32c4c5a73773c58af37bd1b" {
		t.Fatalf("digest = %q", digest)
	}
	data, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "archive bytes" {
		t.Fatalf("downloaded %q", data)
	}
}

func TestDownloadLimit(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "9")
		_, _ = io.WriteString(w, strings.Repeat("x", 9))
	}))
	defer server.Close()
	limits := DefaultDownloadLimits()
	limits.MaxBytes = 8
	client := &Client{HTTPClient: server.Client(), Limits: limits, AllowPrivateHosts: true}
	destination := filepath.Join(t.TempDir(), "archive")
	_, err := client.Download(context.Background(), server.URL, destination)
	if KindOf(err) != KindLimit {
		t.Fatalf("error = %v, kind = %q", err, KindOf(err))
	}
	if _, statErr := os.Stat(destination); !os.IsNotExist(statErr) {
		t.Fatalf("partial destination remains: %v", statErr)
	}
}

func TestDownloadTimeout(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-time.After(100 * time.Millisecond)
		_, _ = io.WriteString(w, "late")
	}))
	defer server.Close()
	limits := DefaultDownloadLimits()
	limits.RequestTimeout = 10 * time.Millisecond
	client := &Client{HTTPClient: server.Client(), Limits: limits, AllowPrivateHosts: true}
	_, err := client.Download(context.Background(), server.URL, filepath.Join(t.TempDir(), "archive"))
	if KindOf(err) != KindDownload {
		t.Fatalf("error = %v, kind = %q", err, KindOf(err))
	}
}
