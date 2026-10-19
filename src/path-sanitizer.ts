import path from 'node:path';
import { SecurityError } from './types.ts';

export class PathSanitizer {
  readonly rootDir: string;

  constructor(rootDir: string) {
    this.rootDir = path.resolve(rootDir);
  }

  resolveSafeDestination(subPath: string, fileName: string): string {
    // 1. Rejeita bytes nulos
    if (subPath.includes('\0') || fileName.includes('\0')) {
      throw new SecurityError('Null-byte injection detectada no caminho do arquivo');
    }

    // 2. Decodificação de possíveis escapes de URL
    let decodedSub = subPath;
    let decodedFile = fileName;
    try {
      decodedSub = decodeURIComponent(subPath);
      decodedFile = decodeURIComponent(fileName);
    } catch {}

    // 3. Normalização
    const combined = path.join(this.rootDir, decodedSub, decodedFile);
    const resolved = path.resolve(combined);

    // 4. Verificação de contenção (jail boundary)
    const relative = path.relative(this.rootDir, resolved);
    if (relative.startsWith('..') || path.isAbsolute(relative)) {
      throw new SecurityError(`Tentativa de path traversal detectada: o destino "${resolved}" escapa da raiz autorizada "${this.rootDir}"`);
    }

    return resolved;
  }
}
