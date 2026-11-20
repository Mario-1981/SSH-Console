import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';

interface TarEntry {
  relPath: string;
  content: Buffer;
  mode: number;
}

function collectEntries(baseDir: string, prefix: string): TarEntry[] {
  const entries: TarEntry[] = [];
  function walk(dir: string) {
    const items = fs.readdirSync(dir, { withFileTypes: true });
    for (const item of items) {
      const fullPath = path.join(dir, item.name);
      if (item.isDirectory()) {
        if (item.name === 'target' || item.name === '.git') continue;
        walk(fullPath);
      } else if (item.isFile()) {
        const rel = path.relative(baseDir, fullPath).split(path.sep).join('/');
        const mode = rel.endsWith('.sh') ? 0o755 : 0o644;
        entries.push({
          relPath: `${prefix}/${rel}`,
          content: fs.readFileSync(fullPath),
          mode,
        });
      }
    }
  }
  walk(baseDir);
  return entries;
}

function buildTarHeader(fileName: string, size: number, mode: number): Buffer {
  const header = Buffer.alloc(512, 0);

  let name = fileName;
  let prefix = '';
  if (Buffer.byteLength(name) > 100) {
    const idx = name.lastIndexOf('/');
    prefix = name.slice(0, idx);
    name = name.slice(idx + 1);
  }

  header.write(name, 0, 100, 'utf8');
  header.write(mode.toString(8).padStart(7, '0') + '\0', 100, 8, 'ascii');
  header.write('0000000\0', 108, 8, 'ascii'); // uid
  header.write('0000000\0', 116, 8, 'ascii'); // gid
  header.write(size.toString(8).padStart(11, '0') + '\0', 124, 12, 'ascii');
  header.write(Math.floor(Date.now() / 1000).toString(8).padStart(11, '0') + '\0', 136, 12, 'ascii');
  header.write('        ', 148, 8, 'ascii'); // checksum placeholder
  header.write('0', 156, 1, 'ascii'); // regular file
  header.write('ustar\0', 257, 6, 'ascii');
  header.write('00', 263, 2, 'ascii');
  header.write('root', 265, 32, 'ascii');
  header.write('root', 297, 32, 'ascii');
  if (prefix) {
    header.write(prefix, 345, 155, 'utf8');
  }

  let checksum = 0;
  for (let i = 0; i < 512; i++) {
    checksum += header[i];
  }
  header.write(checksum.toString(8).padStart(6, '0') + '\0 ', 148, 8, 'ascii');
  return header;
}

export function buildRustProjectTarGz(rustAppDir: string): Buffer {
  const entries = collectEntries(rustAppDir, 'ssh-console-rust');
  const chunks: Buffer[] = [];

  for (const entry of entries) {
    chunks.push(buildTarHeader(entry.relPath, entry.content.length, entry.mode));
    chunks.push(entry.content);
    const remainder = entry.content.length % 512;
    if (remainder !== 0) {
      chunks.push(Buffer.alloc(512 - remainder, 0));
    }
  }

  // Two 512-byte zero blocks mark end of archive
  chunks.push(Buffer.alloc(1024, 0));

  const tarBuffer = Buffer.concat(chunks);
  return zlib.gzipSync(tarBuffer, { level: 9 });
}
