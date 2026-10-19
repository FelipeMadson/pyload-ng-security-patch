import { SecurityError } from './types.ts';

export class SsrfValidator {
  private blockedIps = [
    /^127\./,                    // Loopback IPv4
    /^10\./,                     // Classe A privada
    /^192\.168\./,               // Classe C privada
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // Classe B privada
    /^169\.254\./,               // Link-local / Cloud Metadata
    /^0\.0\.0\.0$/,              // Any local
    /^localhost$/i,
    /^\[?::1\]?$/                // Loopback IPv6
  ];

  assertSafeUrl(rawUrl: string): void {
    let parsed: URL;
    try {
      parsed = new URL(rawUrl);
    } catch {
      throw new SecurityError(`URL inválida ou malformada: ${rawUrl}`);
    }

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new SecurityError(`Protocolo inseguro ou não suportado: ${parsed.protocol}`);
    }

    const hostname = parsed.hostname.toLowerCase();

    for (const pattern of this.blockedIps) {
      if (pattern.test(hostname)) {
        throw new SecurityError(`Acesso bloqueado por política de proteção contra SSRF: ${hostname}`);
      }
    }
  }
}
