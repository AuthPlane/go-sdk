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
//   - IPv6 embedded IPv4 extraction (6to4, IPv4-mapped)
package ssrf

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrSSRFBlocked is returned when a request is blocked by SSRF protection.
var ErrSSRFBlocked = errors.New("ssrf: request blocked by SSRF protection")

// ErrDNSResolution is returned when a hostname cannot be resolved. It is an
// availability failure, not a policy block, so it does not wrap ErrSSRFBlocked.
var ErrDNSResolution = errors.New("ssrf: DNS resolution failed")

// Default limits for response body sizes.
const (
	MaxJWKSSize     int64 = 64 * 1024  // 64 KB
	MaxMetadataSize int64 = 128 * 1024 // 128 KB
	DefaultTimeout        = 10 * time.Second
)

// FetchSettings controls SSRF protection behavior for HTTP requests.
//
// The zero value is the safe one: protection on, https only, public addresses only.
type FetchSettings struct {
	// DisableSSRFProtection skips DNS pinning and address checks. Never set it in production.
	DisableSSRFProtection bool
	AllowHTTP             bool
	AllowLocalhost        bool
	AllowPrivateNets      bool
	Timeout               time.Duration
	// Proxy chooses a proxy for each request, such as http.ProxyFromEnvironment. Nil means
	// none. Addresses are still checked and pinned here, and the SDK never reads a proxy from
	// the environment by itself.
	Proxy func(*http.Request) (*url.URL, error)
	// UserAgent is sent on every fetch. Empty sends the SDK's own.
	UserAgent string
	// Observe, when set, is called after every fetch, for metrics. It must not block.
	Observe func(FetchEvent)
	// RootCAs replaces the system trust store for every fetch, for an authorization
	// server behind a private CA. Nil means system trust.
	RootCAs *x509.CertPool
}

// FetchEvent describes a completed fetch. Its fields hold no query or body. Err may name the
// request path.
type FetchEvent struct {
	Method   string
	Host     string
	Status   int // zero if no response arrived
	Duration time.Duration
	Err      error
}

const defaultUserAgent = "authplane-go-sdk"

// DefaultFetchSettings returns production-safe SSRF fetch settings.
func DefaultFetchSettings() FetchSettings {
	return FetchSettings{
		AllowHTTP:        false,
		AllowLocalhost:   false,
		AllowPrivateNets: false,
		Timeout:          DefaultTimeout,
	}
}

// DevModeFetchSettings returns fetch settings with relaxed SSRF protection for development.
func DevModeFetchSettings() FetchSettings {
	return FetchSettings{
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
	nat64Prefix = &net.IPNet{IP: net.ParseIP("64:ff9b::"), Mask: net.CIDRMask(96, 128)}
	siitPrefix  = &net.IPNet{IP: net.ParseIP("::ffff:0:0:0"), Mask: net.CIDRMask(96, 128)}
)

var (
	alwaysBlockedCIDRs []*net.IPNet
	loopbackCIDRs      []*net.IPNet
	privateCIDRs       []*net.IPNet
)

func init() {
	alwaysBlocked := []string{
		"169.254.0.0/16", "fe80::/10", "224.0.0.0/4", "ff00::/8", "::/128",
		"0.0.0.0/8", "192.0.0.0/24", "198.18.0.0/15", "240.0.0.0/4",
		"fd00:ec2::254/128", // AWS instance metadata over IPv6
		"fd20:ce::254/128",  // Google Cloud instance metadata over IPv6
		"fec0::/10",         // deprecated site-local
		"64:ff9b:1::/48",    // local-use NAT64 (RFC 8215), embedded address not fixed
		"168.63.129.16/32",  // Azure platform services
		"2001::/32",         // Teredo tunnels to an address the guard cannot judge
		"192.0.2.0/24",      // documentation (RFC 5737)
		"198.51.100.0/24",   // documentation (RFC 5737)
		"203.0.113.0/24",    // documentation (RFC 5737)
		"2001:db8::/32",     // documentation (RFC 3849)
		"100::/64",          // discard (RFC 6666)
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
	private := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"}
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
	// An address with an IPv4 address inside it must pass as itself and as what it reaches.
	if innerIP := extractEmbeddedIPv4(ip); innerIP != nil {
		return IsIPAllowed(innerIP, settings)
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
	// NAT64 (RFC 6052), SIIT and ISATAP reach the IPv4 address in the last
	// four octets.
	if nat64Prefix.Contains(ip) || siitPrefix.Contains(ip) || isISATAP(ip) {
		return net.IPv4(ip[12], ip[13], ip[14], ip[15])
	}
	// IPv4-compatible (deprecated, ::a.b.c.d), leaving :: and ::1 to their own rules.
	if isZero(ip[:12]) && !isZero(ip[12:15]) || isZero(ip[:12]) && ip[15] > 1 {
		return net.IPv4(ip[12], ip[13], ip[14], ip[15])
	}
	return nil
}

// isISATAP reports an interface identifier of the form 0[02]00:5efe:a.b.c.d (RFC 5214).
func isISATAP(ip net.IP) bool {
	return (ip[8] == 0x00 || ip[8] == 0x02) && ip[9] == 0x00 && ip[10] == 0x5e && ip[11] == 0xfe
}

func isZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
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
		return nil, fmt.Errorf("%w for %q: %v", ErrDNSResolution, hostname, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: no IPs resolved for %q", ErrSSRFBlocked, hostname)
	}
	var allowedIPs []net.IP
	for _, ip := range ips {
		if !settings.DisableSSRFProtection && !IsIPAllowed(ip, settings) {
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
func SSRFSafeGet(ctx context.Context, rawURL string, settings FetchSettings, maxSize int64) (*HTTPResponse, error) {
	return fetch(ctx, rawURL, settings, fetchRequest{method: http.MethodGet, maxSize: maxSize})
}

//nolint:revive // SSRFSafePost is the established name across all SDKs
func SSRFSafePost(ctx context.Context, rawURL string, settings FetchSettings, opts PostOptions) (*HTTPResponse, error) {
	req := fetchRequest{method: http.MethodPost, maxSize: opts.MaxSize, headers: opts.ExtraHeaders}
	if req.maxSize <= 0 {
		req.maxSize = MaxMetadataSize
	}
	if opts.FormData != nil {
		req.form = opts.FormData.Encode()
		req.hasForm = true
	}
	return fetch(ctx, rawURL, settings, req)
}

type fetchRequest struct {
	method  string
	form    string
	hasForm bool
	headers map[string]string
	maxSize int64
}

func (f fetchRequest) build(ctx context.Context, target string, settings FetchSettings) (*http.Request, error) {
	var body io.Reader = http.NoBody
	if f.hasForm {
		body = strings.NewReader(f.form)
	}
	req, err := http.NewRequestWithContext(ctx, f.method, target, body)
	if err != nil {
		return nil, err
	}
	if f.hasForm {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	userAgent := settings.UserAgent
	if userAgent == "" {
		userAgent = defaultUserAgent
	}
	req.Header.Set("User-Agent", userAgent)
	for k, val := range f.headers {
		req.Header.Set(k, val)
	}
	return req, nil
}

// fetch runs one request through the guard and reports it to settings.Observe.
func fetch(ctx context.Context, rawURL string, settings FetchSettings, f fetchRequest) (*HTTPResponse, error) {
	start := time.Now()
	resp, err := fetchUnobserved(ctx, rawURL, settings, f)
	if settings.Observe != nil {
		event := FetchEvent{Method: f.method, Duration: time.Since(start), Err: err}
		if parsed, parseErr := url.Parse(rawURL); parseErr == nil {
			event.Host = parsed.Host
		}
		if resp != nil {
			event.Status = resp.Status
		}
		settings.Observe(event)
	}
	return resp, err
}

func fetchUnobserved(ctx context.Context, rawURL string, settings FetchSettings, f fetchRequest) (*HTTPResponse, error) {
	if settings.DisableSSRFProtection {
		return unprotectedFetch(ctx, rawURL, settings, f)
	}
	validated, err := ValidateURL(ctx, rawURL, settings)
	if err != nil {
		return nil, err
	}
	return pinnedFetch(ctx, validated, settings, f)
}

// pinnedFetch tries each validated address in turn. It moves to the next only when a connection
// could not be made, since after that a request may already have had its effect.
func pinnedFetch(ctx context.Context, v *ValidatedURL, settings FetchSettings, f fetchRequest) (*HTTPResponse, error) {
	client := pinnedHTTPClient(settings, v.Host)
	var lastErr error
	for _, ip := range v.ResolvedIPs {
		target := fmt.Sprintf("%s://%s:%d%s", v.Scheme, formatIPForURL(ip), v.Port, v.Path)
		req, err := f.build(ctx, target, settings)
		if err != nil {
			return nil, fmt.Errorf("%w: create request: %v", ErrSSRFBlocked, err)
		}
		req.Host = hostHeader(*v)
		resp, err := doLimited(client, req, f.maxSize)
		if err == nil {
			return resp, nil
		}
		lastErr = fmt.Errorf("ssrf: %s %q: %w", f.method, v.Host+v.Path, err)
		if !isConnectFailure(err) || ctx.Err() != nil {
			return nil, lastErr
		}
	}
	return nil, lastErr
}

func doLimited(client *http.Client, req *http.Request, maxSize int64) (*HTTPResponse, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // response body close error is not actionable
	return readLimitedResponse(resp, maxSize)
}

func isConnectFailure(err error) bool {
	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == "dial"
}

func requestTimeout(settings FetchSettings) time.Duration {
	if settings.Timeout <= 0 {
		return DefaultTimeout
	}
	return settings.Timeout
}

func refuseRedirect(*http.Request, []*http.Request) error {
	return fmt.Errorf("%w: redirects are not allowed", ErrSSRFBlocked)
}

// transportKey names what makes pinned transports differ. Pooling them per host keeps
// connections alive across requests, so a verified token does not cost a new TLS handshake.
type transportKey struct {
	host  string
	roots *x509.CertPool
}

const (
	maxPooledTransports = 64
	dialTimeout         = 5 * time.Second
)

var (
	transportsMu sync.Mutex
	transports   = map[transportKey]*http.Transport{}
)

func pinnedTransport(settings FetchSettings, host string) *http.Transport {
	// Two proxy functions cannot be told apart, so one with a proxy has its own transport and
	// no idle connections, rather than risk another client's traffic going through it.
	if settings.Proxy != nil {
		return &http.Transport{
			Proxy:             settings.Proxy,
			DialContext:       (&net.Dialer{Timeout: dialTimeout}).DialContext,
			TLSClientConfig:   &tls.Config{ServerName: host, RootCAs: settings.RootCAs},
			DisableKeepAlives: true,
		}
	}
	key := transportKey{host: host, roots: settings.RootCAs}
	transportsMu.Lock()
	defer transportsMu.Unlock()
	if t, ok := transports[key]; ok {
		return t
	}
	if len(transports) >= maxPooledTransports {
		for k, t := range transports {
			t.CloseIdleConnections()
			delete(transports, k)
		}
	}
	t := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: dialTimeout}).DialContext,
		TLSClientConfig:     &tls.Config{ServerName: host, RootCAs: settings.RootCAs},
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     90 * time.Second,
	}
	transports[key] = t
	return t
}

func pinnedHTTPClient(settings FetchSettings, originalHost string) *http.Client {
	return &http.Client{
		Timeout:       requestTimeout(settings),
		Transport:     pinnedTransport(settings, originalHost),
		CheckRedirect: refuseRedirect,
	}
}

// unprotectedTransport has no SSRF checks. Like the protected one, it reads no proxy from the
// environment.
func unprotectedTransport(settings FetchSettings) http.RoundTripper {
	return &http.Transport{
		Proxy:             settings.Proxy,
		TLSClientConfig:   &tls.Config{RootCAs: settings.RootCAs},
		DisableKeepAlives: true,
	}
}

func unprotectedFetch(ctx context.Context, rawURL string, settings FetchSettings, f fetchRequest) (*HTTPResponse, error) {
	client := &http.Client{
		Timeout:       requestTimeout(settings),
		Transport:     unprotectedTransport(settings),
		CheckRedirect: refuseRedirect,
	}
	req, err := f.build(ctx, rawURL, settings)
	if err != nil {
		return nil, fmt.Errorf("ssrf: create request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ssrf: %s: %w", f.method, err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body close error is not actionable
	return readLimitedResponse(resp, f.maxSize)
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

// hostHeader returns the value for the outbound HTTP Host header.
//
// Per RFC 9110 §7.2 the Host header must mirror the URI authority, including
// the port when it is not the scheme's default. This is required for RFC 9449
// DPoP htu validation: the Authorization Server reconstructs the request URI
// from the Host header and compares it against the proof's htu, so dropping a
// non-default port (e.g. :9000) breaks the match. IPv6 literals are bracketed
// per RFC 3986 §3.2.2.
func hostHeader(v ValidatedURL) string {
	defaultPort := 80
	if v.Scheme == "https" {
		defaultPort = 443
	}
	if v.Port == defaultPort {
		if strings.Contains(v.Host, ":") {
			return "[" + v.Host + "]"
		}
		return v.Host
	}
	return net.JoinHostPort(v.Host, strconv.Itoa(v.Port))
}

func formatIPForURL(ip net.IP) string {
	if ip.To4() != nil {
		return ip.String()
	}
	return "[" + ip.String() + "]"
}
