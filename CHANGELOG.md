# Changelog

All notable changes to `laravel-ssrf-guard` will be documented in this file.

## v1.2.0 - 2026-11-23

### Security

Fixes [GHSA-4rq2-jjv2-p22v](https://github.com/jeffersongoncalves/laravel-ssrf-guard/security/advisories/GHSA-4rq2-jjv2-p22v) (CWE-918, CVSS 6.8): IPv6 transition addresses embedding loopback, RFC1918 or cloud-metadata IPv4 addresses were classified as public in the default configuration.

`isPublicIp()` now rejects these IPv4-embedding forms:

- IPv4-translated `::ffff:0:0:0/96` (RFC 2765)
- NAT64 local-use `64:ff9b:1::/48` (RFC 8215)
- Teredo `2001::/32` (RFC 4380)
- 6to4 `2002::/16` (RFC 3056)
- ISATAP interface identifiers `0000:5efe` / `0200:5efe` under any prefix (RFC 5214)

**Behavior change:** these forms are now blocked regardless of the embedded IPv4, so 6to4/ISATAP addresses wrapping a *public* IPv4 are rejected too, consistent with the existing policy of rejecting IPv4-wrapped IPv6 literals outright.

**Known residual:** operator-chosen NAT64 prefixes (RFC 6052 network-specific) cannot be enumerated and are not covered.

All users should upgrade.

Thanks to @Epsilon0xCell for the responsible disclosure.

## v1.1.1 - 2026-10-28

- Harden host pinning and IPv6 resolve entries.

## v1.1.0 - 2026-06-21

**Full Changelog**: https://github.com/jeffersongoncalves/laravel-ssrf-guard/compare/v1.0.1...v1.1.0

## v1.0.1 - 2026-06-20

chore: ignore the .phpunit.cache directory.

## v1.0.0 - 2026-06-20

Initial release.
