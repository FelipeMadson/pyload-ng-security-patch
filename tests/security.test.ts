import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { PathSanitizer } from '../src/path-sanitizer.ts';
import { SsrfValidator } from '../src/ssrf-validator.ts';
import { SecurityError } from '../src/types.ts';

describe('PathSanitizer', () => {
  const root = process.platform === 'win32' ? 'C:\\data\\downloads' : '/data/downloads';
  const sanitizer = new PathSanitizer(root);

  it('permite caminhos válidos dentro da pasta raiz', () => {
    const safe = sanitizer.resolveSafeDestination('docs', 'report.pdf');
    assert.ok(safe.includes('report.pdf'));
  });

  it('bloqueia tentativas clássicas de path traversal (../etc/passwd)', () => {
    assert.throws(
      () => sanitizer.resolveSafeDestination('../../etc', 'passwd'),
      SecurityError
    );
  });

  it('bloqueia injeção de byte nulo', () => {
    assert.throws(
      () => sanitizer.resolveSafeDestination('sub', 'file.exe\0.jpg'),
      SecurityError
    );
  });
});

describe('SsrfValidator', () => {
  const validator = new SsrfValidator();

  it('permite domínios públicos regulares', () => {
    assert.doesNotThrow(() => validator.assertSafeUrl('https://example.com/file.zip'));
    assert.doesNotThrow(() => validator.assertSafeUrl('https://api.github.com/repos'));
  });

  it('bloqueia acessos a localhost e 127.0.0.1', () => {
    assert.throws(() => validator.assertSafeUrl('http://127.0.0.1/admin'), SecurityError);
    assert.throws(() => validator.assertSafeUrl('http://localhost:8080/metrics'), SecurityError);
  });

  it('bloqueia acesso ao IP de metadata da AWS / nuvem (169.254.169.254)', () => {
    assert.throws(
      () => validator.assertSafeUrl('http://169.254.169.254/latest/meta-data/'),
      SecurityError
    );
  });
});
