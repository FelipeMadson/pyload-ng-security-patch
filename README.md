# pyLoad-ng Security Patch & Hardening Suite

Defensive hardening module and vulnerability mitigation patch protecting download pipeline engines, web extractors, and file processors against arbitrary path traversal, null-byte injection, and Server-Side Request Forgery (SSRF).

[![CI](https://github.com/FelipeMadson/pyload-ng-security-patch/actions/workflows/ci.yml/badge.svg)](https://github.com/FelipeMadson/pyload-ng-security-patch/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

*Read this in [Português](README.pt-BR.md).*

---

## Threat Model & Mitigations

- **Path Traversal Defense**: Strictly enforces filesystem confinement to authorized target roots. Rejects dot-dot sequences (`../`, `..\\`), Unicode homoglyph escapes (`%2e%2e%2f`), null bytes (`\0`), and symlink escapes.
- **SSRF Blocker**: Prohibits requests targeting loopback addresses (`127.0.0.1`, `::1`), private RFC 1918 networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and cloud instance metadata services (`169.254.169.254`).
- **Streaming Integrity Verification**: Verifies SHA-256 and MD5 checksum digests on the fly.

---

## Usage

```typescript
import { PathSanitizer, SsrfValidator } from './src/index.ts';

// 1. Path confinement
const sanitizer = new PathSanitizer('/data/downloads');
const safePath = sanitizer.resolveSafeDestination('user_subfolder', 'file.zip');
// Throws SecurityError on: '../../etc/passwd'

// 2. SSRF validation
const ssrf = new SsrfValidator();
ssrf.assertSafeUrl('https://example.com/archive.tar.gz');
// Throws SecurityError on: 'http://169.254.169.254/latest/meta-data'
```

## License

MIT © [Felipe Madison](https://github.com/FelipeMadson)
