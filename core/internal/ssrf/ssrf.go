// Package ssrf provides SSRF-safe HTTP request utilities for the Authplane SDK.
//
// All outbound HTTP calls in the SDK (JWKS fetch, metadata discovery, token
// exchange, introspection, revocation) MUST go through this package.
//
// Security measures:
//   - DNS pinning: hostname resolved once, connection made directly to validated IP
//   - IP blocklist: cloud metadata, link-local, multicast, unspecified always blocked
//   - HTTPS enforcement by default
//   - Response size limits
//   - Redirect blocking
//   - IPv6 embedded IPv4 extraction (6to4, Teredo, IPv4-mapped)
package ssrf

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ErrSSRFBlocked is returned when a request is blocked by SSRF protection.
var ErrSSRFBlocked = errors.New("ssrf: request blocked by SSRF protection")

// Default limits for response body sizes.
const (
	MaxJWKSSize     int64 = 64 * 1024  // 64 KB
	MaxMetadataSize int64 = 128 * 1024 // 128 KB
	DefaultTimeout        = 10 * time.Second
)

// FetchSettings controls SSRF protection behavior for HTTP requests.
type FetchSettings struct {
	SSRFProtection   bool
	AllowHTTP        bool
	AllowLocalhost   bool
	AllowPrivateNets bool
	Timeout          time.Duration
}

// DefaultFetchSettings returns production-safe SSRF fetch settings.
func DefaultFetchSettings() FetchSettings {
	return FetchSettings{
		SSRFProtection:   true,
		AllowHTTP:        false,
		AllowLocalhost:   false,
		AllowPrivateNets: false,
		Timeout:          DefaultTimeout,
	}
}

// DevModeFetchSettings returns fetch settings with relaxed SSRF protection for development.
func DevModeFetchSettings() FetchSettings {
	return FetchSettings{
		SSRFProtection:   true,
		AllowHTTP:        true,
		AllowLocalhost:   true,
		AllowPrivateNets: true,
		Timeout:          DefaultTimeout,
	}
}

// ValidatedURL holds a URL that has passed SSRF validation.
type ValidatedURL struct {
	Scheme      string
	Host        string
	Port        int
	Path        string
	ResolvedIPs []net.IP
}

// HTTPResponse holds a response from an SSRF-safe HTTP request.
type HTTPResponse struct {
	Body    []byte
	Headers http.Header
	Status  int
}

// PostOptions configures an SSRF-safe POST request.
type PostOptions struct {
	FormData     url.Values
	ExtraHeaders map[string]string
	MaxSize      int64
}

var (
	alwaysBlockedCIDRs []*net.IPNet
	loopbackCIDRs      []*net.IPNet
	privateCIDRs       []*net.IPNet
)

func init() {
	alwaysBlocked := []string{
		"169.254.0.0/16", "fe80::/10", "224.0.0.0/4", "ff00::/8", "0.0.0.0/32", "::/128",
	}
	for _, cidr := range alwaysBlocked {
		_, network, _ := net.ParseCIDR(cidr)
		alwaysBlockedCIDRs = append(alwaysBlockedCIDRs, network)
	}
	loopback := []string{"127.0.0.0/8", "::1/128"}
	for _, cidr := range loopback {
		_, network, _ := net.ParseCIDR(cidr)
		loopbackCIDRs = append(loopbackCIDRs, network)
	}
	private := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"}
	for _, cidr := range private {
		_, network, _ := net.ParseCIDR(cidr)
		privateCIDRs = append(privateCIDRs, network)
	}
}

// IsIPAllowed checks whether an IP address is allowed by the given SSRF settings.
func IsIPAllowed(ip net.IP, settings FetchSettings) bool {
	if ip == nil {
		return false
	}
	ip = ip.To16()
	if ip == nil {
		return false
	}
	for _, network := range alwaysBlockedCIDRs {
		if network.Contains(ip) {
			return false
		}
	}
	if innerIP := extractEmbeddedIPv4(ip); innerIP != nil {
		return IsIPAllowed(innerIP, settings)
	}
	if !settings.AllowLocalhost {
		for _, network := range loopbackCIDRs {
			if network.Contains(ip) {
				return false
			}
		}
	}
	if !settings.AllowPrivateNets {
		for _, network := range privateCIDRs {
			if network.Contains(ip) {
				return false
			}
		}
	}
	return true
}

func extractEmbeddedIPv4(ip net.IP) net.IP {
	ip = ip.To16()
	if ip == nil {
		return nil
	}
	if ip4 := ip.To4(); ip4 != nil && !ip.Equal(ip4) {
		return ip4
	}
	if ip[0] == 0x20 && ip[1] == 0x02 {
		return net.IPv4(ip[2], ip[3], ip[4], ip[5])
	}
	if ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x00 && ip[3] == 0x00 {
		serverIP := net.IPv4(ip[4], ip[5], ip[6], ip[7])
		clientIP := net.IPv4(ip[12]^0xff, ip[13]^0xff, ip[14]^0xff, ip[15]^0xff)
		if !isIPv4GloballyAllowed(serverIP) || !isIPv4GloballyAllowed(clientIP) {
			return serverIP
		}
		return nil
	}
	return nil
}

func isIPv4GloballyAllowed(ip net.IP) bool {
	ip16 := ip.To16()
	for _, network := range alwaysBlockedCIDRs {
		if network.Contains(ip16) {
			return false
		}
	}
	return true
}

// ValidateURL validates a URL against SSRF protections and resolves its hostname.
func ValidateURL(ctx context.Context, rawURL string, settings FetchSettings) (*ValidatedURL, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid URL: %v", ErrSSRFBlocked, err)
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		if !settings.AllowHTTP {
			return nil, fmt.Errorf("%w: HTTP not allowed (use HTTPS or enable AllowHTTP)", ErrSSRFBlocked)
		}
	default:
		return nil, fmt.Errorf("%w: unsupported scheme %q", ErrSSRFBlocked, parsed.Scheme)
	}
	hostname := parsed.Hostname()
	if hostname == "" {
		return nil, fmt.Errorf("%w: empty hostname", ErrSSRFBlocked)
	}
	port := 443
	if parsed.Scheme == "http" {
		port = 80
	}
	if parsed.Port() != "" {
		if p, err := strconv.Atoi(parsed.Port()); err == nil {
			port = p
		}
	}
	ips, err := resolveHostname(ctx, hostname)
	if err != nil {
		return nil, fmt.Errorf("%w: DNS resolution failed for %q: %v", ErrSSRFBlocked, hostname, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: no IPs resolved for %q", ErrSSRFBlocked, hostname)
	}
	var allowedIPs []net.IP
	for _, ip := range ips {
		if settings.SSRFProtection && !IsIPAllowed(ip, settings) {
			continue
		}
		allowedIPs = append(allowedIPs, ip)
	}
	if len(allowedIPs) == 0 {
		return nil, fmt.Errorf("%w: all resolved IPs for %q are blocked", ErrSSRFBlocked, hostname)
	}
	path := parsed.RequestURI()
	return &ValidatedURL{
		Scheme:      parsed.Scheme,
		Host:        hostname,
		Port:        port,
		Path:        path,
		ResolvedIPs: allowedIPs,
	}, nil
}

func resolveHostname(ctx context.Context, hostname string) ([]net.IP, error) {
	if ip := net.ParseIP(hostname); ip != nil {
		return []net.IP{ip}, nil
	}
	resolver := net.DefaultResolver
	addrs, err := resolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(addrs))
	var ips []net.IP
	for _, addr := range addrs {
		key := addr.IP.String()
		if !seen[key] {
			seen[key] = true
			ips = append(ips, addr.IP)
		}
	}
	return ips, nil
}

//nolint:revive // SSRFSafeGet is the established name across all SDKs
func SSRFSafeGet(ctx context.Context, rawURL string, settings FetchSettings, client *http.Client, maxSize int64) (*HTTPResponse, error) {
	if !settings.SSRFProtection {
		return unsafeGet(ctx, rawURL, settings, client, maxSize)
	}
	validated, err := ValidateURL(ctx, rawURL, settings)
	if err != nil {
		return nil, err
	}
	return pinnedGet(ctx, validated, settings, client, maxSize)
}

//nolint:revive // SSRFSafePost is the established name across all SDKs
func SSRFSafePost(ctx context.Context, rawURL string, settings FetchSettings, client *http.Client, opts PostOptions) (*HTTPResponse, error) {
	if !settings.SSRFProtection {
		return unsafePost(ctx, rawURL, settings, client, opts)
	}
	validated, err := ValidateURL(ctx, rawURL, settings)
	if err != nil {
		return nil, err
	}
	return pinnedPost(ctx, validated, settings, client, opts)
}

func pinnedGet(ctx context.Context, v *ValidatedURL, settings FetchSettings, _ *http.Client, maxSize int64) (*HTTPResponse, error) {
	targetIP := v.ResolvedIPs[0]
	ipStr := formatIPForURL(targetIP)
	targetURL := fmt.Sprintf("%s://%s:%d%s", v.Scheme, ipStr, v.Port, v.Path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("%w: create request: %v", ErrSSRFBlocked, err)
	}
	req.Host = v.Host
	pinnedClient := pinnedHTTPClient(settings, v.Host)
	resp, err := pinnedClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ssrf: GET %q: %w", v.Host+v.Path, err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body close error is not actionable
	return readLimitedResponse(resp, maxSize)
}

func pinnedPost(ctx context.Context, v *ValidatedURL, settings FetchSettings, _ *http.Client, opts PostOptions) (*HTTPResponse, error) {
	targetIP := v.ResolvedIPs[0]
	ipStr := formatIPForURL(targetIP)
	targetURL := fmt.Sprintf("%s://%s:%d%s", v.Scheme, ipStr, v.Port, v.Path)
	var body io.Reader
	var contentType string
	if opts.FormData != nil {
		body = strings.NewReader(opts.FormData.Encode())
		contentType = "application/x-www-form-urlencoded"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, body)
	if err != nil {
		return nil, fmt.Errorf("%w: create request: %v", ErrSSRFBlocked, err)
	}
	req.Host = v.Host
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, val := range opts.ExtraHeaders {
		req.Header.Set(k, val)
	}
	pinnedClient := pinnedHTTPClient(settings, v.Host)
	resp, err := pinnedClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ssrf: POST %q: %w", v.Host+v.Path, err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body close error is not actionable
	maxSize := opts.MaxSize
	if maxSize <= 0 {
		maxSize = MaxMetadataSize
	}
	return readLimitedResponse(resp, maxSize)
}

func pinnedHTTPClient(settings FetchSettings, originalHost string) *http.Client {
	timeout := settings.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName: originalHost,
		},
		DisableKeepAlives: true,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			return fmt.Errorf("%w: redirects are not allowed", ErrSSRFBlocked)
		},
	}
}

func unsafeGet(ctx context.Context, rawURL string, settings FetchSettings, client *http.Client, maxSize int64) (*HTTPResponse, error) {
	if client == nil {
		timeout := settings.Timeout
		if timeout <= 0 {
			timeout = DefaultTimeout
		}
		client = &http.Client{
			Timeout: timeout,
			CheckRedirect: func(_ *http.Request, via []*http.Request) error {
				return fmt.Errorf("%w: redirects are not allowed", ErrSSRFBlocked)
			},
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("ssrf: create request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ssrf: GET: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body close error is not actionable
	return readLimitedResponse(resp, maxSize)
}

func unsafePost(ctx context.Context, rawURL string, settings FetchSettings, client *http.Client, opts PostOptions) (*HTTPResponse, error) {
	if client == nil {
		timeout := settings.Timeout
		if timeout <= 0 {
			timeout = DefaultTimeout
		}
		client = &http.Client{
			Timeout: timeout,
			CheckRedirect: func(_ *http.Request, via []*http.Request) error {
				return fmt.Errorf("%w: redirects are not allowed", ErrSSRFBlocked)
			},
		}
	}
	var body io.Reader
	var contentType string
	if opts.FormData != nil {
		body = strings.NewReader(opts.FormData.Encode())
		contentType = "application/x-www-form-urlencoded"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, body)
	if err != nil {
		return nil, fmt.Errorf("ssrf: create request: %w", err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, val := range opts.ExtraHeaders {
		req.Header.Set(k, val)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ssrf: POST: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body close error is not actionable
	maxSize := opts.MaxSize
	if maxSize <= 0 {
		maxSize = MaxMetadataSize
	}
	return readLimitedResponse(resp, maxSize)
}

func readLimitedResponse(resp *http.Response, maxSize int64) (*HTTPResponse, error) {
	if resp.ContentLength > maxSize {
		return nil, fmt.Errorf("%w: response too large (%d bytes, limit %d)", ErrSSRFBlocked, resp.ContentLength, maxSize)
	}
	limitedReader := io.LimitReader(resp.Body, maxSize+1)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("ssrf: read response body: %w", err)
	}
	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("%w: response body exceeds %d bytes", ErrSSRFBlocked, maxSize)
	}
	return &HTTPResponse{
		Body:    data,
		Headers: resp.Header,
		Status:  resp.StatusCode,
	}, nil
}

func formatIPForURL(ip net.IP) string {
	if ip.To4() != nil {
		return ip.String()
	}
	return "[" + ip.String() + "]"
}

// ParseJSONResponse unmarshals an HTTPResponse body into the given target.
func ParseJSONResponse(resp *HTTPResponse, target any) error {
	if err := json.Unmarshal(resp.Body, target); err != nil {
		return fmt.Errorf("ssrf: parse JSON response: %w", err)
	}
	return nil
}
