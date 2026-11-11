package oauth

import (
	"fmt"
	"log/slog"
)

const redacted = "[REDACTED]"

// Redact returns a placeholder for a set secret, and an empty string for an unset one, so a
// log still shows whether the value was there.
func Redact(secret string) string {
	if secret == "" {
		return ""
	}
	return redacted
}

// String keeps the client secret and signing key out of logs and %v.
func (a ClientAuthentication) String() string {
	key := ""
	if a.SigningKey != nil {
		key = redacted
	}
	return fmt.Sprintf("{Method:%s ClientID:%s ClientSecret:%s SigningKey:%s}", a.Method, a.ClientID, Redact(a.ClientSecret), key)
}

// GoString keeps secrets out of %#v.
func (a ClientAuthentication) GoString() string { return a.String() }

// LogValue keeps secrets out of structured logs.
func (a ClientAuthentication) LogValue() slog.Value { return slog.StringValue(a.String()) }

// String keeps the tokens out of logs and %v.
func (r TokenResponse) String() string {
	return fmt.Sprintf("{AccessToken:%s TokenType:%s Scope:%s RefreshToken:%s}", Redact(r.AccessToken), r.TokenType, r.Scope, Redact(r.RefreshToken))
}

// GoString keeps the tokens out of %#v.
func (r TokenResponse) GoString() string { return r.String() }

// LogValue keeps the tokens out of structured logs.
func (r TokenResponse) LogValue() slog.Value { return slog.StringValue(r.String()) }

// String keeps the tokens out of logs and %v.
func (in TokenExchangeInput) String() string {
	return fmt.Sprintf("{SubjectToken:%s ActorToken:%s}", Redact(in.SubjectToken), Redact(in.ActorToken))
}

// GoString keeps the tokens out of %#v.
func (in TokenExchangeInput) GoString() string { return in.String() }

// LogValue keeps the tokens out of structured logs.
func (in TokenExchangeInput) LogValue() slog.Value { return slog.StringValue(in.String()) }

// String keeps the assertion out of logs and %v.
func (in JWTBearerInput) String() string {
	return fmt.Sprintf("{Assertion:%s}", Redact(in.Assertion))
}

// GoString keeps the assertion out of %#v.
func (in JWTBearerInput) GoString() string { return in.String() }

// LogValue keeps the assertion out of structured logs.
func (in JWTBearerInput) LogValue() slog.Value { return slog.StringValue(in.String()) }
