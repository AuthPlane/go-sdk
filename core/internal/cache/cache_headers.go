package cache

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ParseCacheExpiry extracts the cache expiry time from HTTP response headers.
func ParseCacheExpiry(headers http.Header) time.Time {
	if cc := headers.Get("Cache-Control"); cc != "" {
		if maxAge := parseMaxAge(cc); maxAge > 0 {
			return time.Now().Add(time.Duration(maxAge) * time.Second)
		}
		lower := strings.ToLower(cc)
		if strings.Contains(lower, "no-cache") || strings.Contains(lower, "no-store") {
			return time.Time{}
		}
	}
	if expires := headers.Get("Expires"); expires != "" {
		t, err := http.ParseTime(expires)
		if err == nil {
			return t
		}
	}
	return time.Time{}
}

func parseMaxAge(cacheControl string) int64 {
	for directive := range strings.SplitSeq(cacheControl, ",") {
		directive = strings.TrimSpace(directive)
		lower := strings.ToLower(directive)
		if val, ok := strings.CutPrefix(lower, "max-age="); ok {
			val = strings.TrimSpace(val)
			n, err := strconv.ParseInt(val, 10, 64)
			if err == nil && n >= 0 {
				return n
			}
		}
	}
	return 0
}
