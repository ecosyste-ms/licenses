package archive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const userAgent = "licenses.ecosyste.ms/v2"

// DownloadLimits bounds remote archive requests.
type DownloadLimits struct {
	MaxBytes       int64
	MaxRedirects   int
	ConnectTimeout time.Duration
	HeaderTimeout  time.Duration
	RequestTimeout time.Duration
}

// DefaultDownloadLimits returns conservative production defaults.
func DefaultDownloadLimits() DownloadLimits {
	return DownloadLimits{
		MaxBytes:       100 << 20,
		MaxRedirects:   5,
		ConnectTimeout: 10 * time.Second,
		HeaderTimeout:  20 * time.Second,
		RequestTimeout: 60 * time.Second,
	}
}

// Client downloads archives. HTTPClient is injectable for local fixture
// servers; production should use NewSafeHTTPClient.
type Client struct {
	HTTPClient        *http.Client
	Limits            DownloadLimits
	AllowPrivateHosts bool // Test fixtures only; production must leave this false.
}

// NewClient constructs a production client that blocks non-public networks.
func NewClient(limits DownloadLimits) *Client {
	return &Client{HTTPClient: NewSafeHTTPClient(limits), Limits: limits}
}

// NewSafeHTTPClient returns an HTTP client whose dialer validates every
// resolved address and whose redirect policy revalidates every destination.
func NewSafeHTTPClient(limits DownloadLimits) *http.Client {
	dialer := &net.Dialer{Timeout: limits.ConnectTimeout, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		DialContext:           safeDialContext(dialer),
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   limits.ConnectTimeout,
		ResponseHeaderTimeout: limits.HeaderTimeout,
		IdleConnTimeout:       90 * time.Second,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   limits.RequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= limits.MaxRedirects {
				return errors.New("redirect limit exceeded")
			}
			if err := ValidateURL(req.URL); err != nil {
				return err
			}
			return nil
		},
	}
}

func safeDialContext(dialer *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return validatedDialContext(net.DefaultResolver.LookupNetIP, dialer.DialContext)
}

func validatedDialContext(
	lookup func(context.Context, string, string) ([]netip.Addr, error),
	dial func(context.Context, string, string) (net.Conn, error),
) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("invalid destination: %w", err)
		}
		addresses, err := lookup(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("resolving destination: %w", err)
		}
		if len(addresses) == 0 {
			return nil, errors.New("destination has no addresses")
		}
		for _, address := range addresses {
			if !IsPublicIP(address.Unmap()) {
				return nil, fmt.Errorf("destination resolves to blocked address %s", address)
			}
		}
		var lastErr error
		for _, resolved := range addresses {
			conn, err := dial(ctx, network, net.JoinHostPort(resolved.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}

// IsPublicIP reports whether addr is safe for a user-selected remote request.
func IsPublicIP(addr netip.Addr) bool {
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsLoopback() ||
		addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
		addr.IsMulticast() || addr.IsInterfaceLocalMulticast() {
		return false
	}
	// RFC 6598 shared address space is not considered globally reachable by
	// netip, but spell it out to keep this boundary obvious.
	if prefix := netip.MustParsePrefix("100.64.0.0/10"); prefix.Contains(addr) {
		return false
	}
	return addr.IsGlobalUnicast()
}

// ValidateURL validates the URL shape before any network activity.
func ValidateURL(parsed *url.URL) error {
	if err := validateURLShape(parsed); err != nil {
		return err
	}
	if ip, err := netip.ParseAddr(strings.Trim(parsed.Hostname(), "[]")); err == nil && !IsPublicIP(ip.Unmap()) {
		return errors.New("URL address is not public")
	}
	return nil
}

func validateURLShape(parsed *url.URL) error {
	if parsed == nil {
		return errors.New("URL is required")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("only HTTP and HTTPS URLs are supported")
	}
	if parsed.Hostname() == "" {
		return errors.New("URL hostname is required")
	}
	if parsed.User != nil {
		return errors.New("URL credentials are not allowed")
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.ParseUint(port, 10, 16)
		if err != nil || value == 0 {
			return errors.New("URL port is invalid")
		}
	}
	return nil
}

// Download streams rawURL into destination and returns the content SHA-256.
func (c *Client) Download(ctx context.Context, rawURL, destination string) (string, error) {
	if c == nil || c.HTTPClient == nil {
		return "", wrap(KindDownload, "download", errors.New("HTTP client is not configured"))
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", wrap(KindInvalid, "validate URL", err)
	}
	validate := ValidateURL
	if c.AllowPrivateHosts {
		validate = validateURLShape
	}
	if err := validate(parsed); err != nil {
		return "", wrap(KindInvalid, "validate URL", err)
	}
	if c.Limits.MaxBytes <= 0 {
		return "", wrap(KindInvalid, "validate limits", errors.New("download byte limit must be positive"))
	}

	requestCtx := ctx
	var cancel context.CancelFunc
	if c.Limits.RequestTimeout > 0 {
		requestCtx, cancel = context.WithTimeout(ctx, c.Limits.RequestTimeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return "", wrap(KindInvalid, "create request", err)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/octet-stream, application/zip, application/gzip, application/x-tar")
	req.Header.Set("Accept-Encoding", "identity")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", wrap(KindDownload, "download archive", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", wrap(KindDownload, "download archive", fmt.Errorf("upstream returned HTTP %d", resp.StatusCode))
	}
	if resp.ContentLength > c.Limits.MaxBytes {
		return "", wrap(KindLimit, "download archive", fmt.Errorf("compressed archive exceeds %d bytes", c.Limits.MaxBytes))
	}

	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", wrap(KindDownload, "create archive file", err)
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(destination)
		}
	}()

	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(file, hash), io.LimitReader(resp.Body, c.Limits.MaxBytes+1))
	if err != nil {
		return "", wrap(KindDownload, "read archive", err)
	}
	if written > c.Limits.MaxBytes {
		return "", wrap(KindLimit, "download archive", fmt.Errorf("compressed archive exceeds %d bytes", c.Limits.MaxBytes))
	}
	if err := file.Sync(); err != nil {
		return "", wrap(KindDownload, "sync archive", err)
	}
	remove = false
	return hex.EncodeToString(hash.Sum(nil)), nil
}
