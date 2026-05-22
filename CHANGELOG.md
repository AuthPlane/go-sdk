# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-05-22

### Fixed

- DPoP `htu` validation against Authorization Servers on non-default ports. The
  SSRF-safe pinned HTTP client now keeps a non-default port in the `Host` header,
  and DPoP proof generation normalizes the `htu` claim to match: an explicit
  default port (`:80`/`:443`) is dropped, non-default ports are preserved, IPv6
  literals stay bracketed, and any userinfo is stripped from `htu`
  (RFC 9110 §7.2, RFC 9449 §4.3).

## [0.1.0] - 2026-05-17

- Initial release.
