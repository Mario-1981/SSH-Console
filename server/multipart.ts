import type { Request } from 'express';

export interface ParsedMultipartFile {
  filename: string;
  content: string;
}

export interface ParsedMultipartData {
  fields: Record<string, string>;
  files: Record<string, ParsedMultipartFile>;
}

function extractBoundary(contentType: string): string | null {
  const match = contentType.match(/boundary=(?:"([^"]+)"|([^;\s]+))/i);
  const raw = match?.[1] ?? match?.[2];
  return raw ? raw.trim() : null;
}

function parseContentDisposition(headerValue: string): { name?: string; filename?: string } {
  const nameMatch = headerValue.match(/;\s*name="([^"]*)"/i) ?? headerValue.match(/;\s*name=([^;\s]+)/i);
  const filenameMatch =
    headerValue.match(/;\s*filename="([^"]*)"/i) ?? headerValue.match(/;\s*filename=([^;\s]+)/i);
  return {
    name: nameMatch?.[1]?.trim(),
    filename: filenameMatch?.[1]?.trim(),
  };
}

export async function parseMultipartFormData(
  req: Request,
  maxBytes = 2 * 1024 * 1024
): Promise<ParsedMultipartData> {
  const contentType = String(req.headers['content-type'] ?? '');
  const boundary = extractBoundary(contentType);
  if (!boundary) {
    throw new Error('Ungültiger Content-Type: multipart/form-data Boundary fehlt.');
  }

  const bodyBuffer = await new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;

    const fail = (err: Error) => {
      if (settled) return;
      settled = true;
      reject(err);
    };

    req.on('data', (chunk: Buffer | string) => {
      if (settled) return;
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += buf.length;
      if (total > maxBytes) {
        fail(new Error('Upload überschreitet das Größenlimit von 2 MB.'));
        req.resume();
        return;
      }
      chunks.push(buf);
    });

    req.on('end', () => {
      if (settled) return;
      settled = true;
      resolve(Buffer.concat(chunks));
    });

    req.on('error', (err) => fail(err instanceof Error ? err : new Error(String(err))));
    req.on('aborted', () => fail(new Error('Upload wurde vorzeitig abgebrochen.')));
  });

  const fields: Record<string, string> = {};
  const files: Record<string, ParsedMultipartFile> = {};

  const delimiter = Buffer.from(`--${boundary}`);
  const headerSepCrlf = Buffer.from('\r\n\r\n');
  const headerSepLf = Buffer.from('\n\n');

  let pos = bodyBuffer.indexOf(delimiter);
  if (pos === -1) {
    throw new Error('Keine gültigen Multipart-Teile im Request-Body gefunden.');
  }

  while (pos !== -1) {
    let partStart = pos + delimiter.length;

    // End boundary marker "--"
    if (bodyBuffer.subarray(partStart, partStart + 2).toString('utf8') === '--') {
      break;
    }

    // Skip CRLF or LF after boundary
    if (bodyBuffer[partStart] === 0x0d && bodyBuffer[partStart + 1] === 0x0a) {
      partStart += 2;
    } else if (bodyBuffer[partStart] === 0x0a) {
      partStart += 1;
    }

    const nextPos = bodyBuffer.indexOf(delimiter, partStart);
    if (nextPos === -1) break;

    let partEnd = nextPos;
    if (partEnd >= 2 && bodyBuffer[partEnd - 2] === 0x0d && bodyBuffer[partEnd - 1] === 0x0a) {
      partEnd -= 2;
    } else if (partEnd >= 1 && bodyBuffer[partEnd - 1] === 0x0a) {
      partEnd -= 1;
    }

    const part = bodyBuffer.subarray(partStart, partEnd);
    let sepIdx = part.indexOf(headerSepCrlf);
    let sepLen = 4;
    if (sepIdx === -1) {
      sepIdx = part.indexOf(headerSepLf);
      sepLen = 2;
    }

    if (sepIdx !== -1) {
      const headerText = part.subarray(0, sepIdx).toString('utf8');
      const valueText = part.subarray(sepIdx + sepLen).toString('utf8');

      const headerLines = headerText.split(/\r?\n/);
      let disposition = '';
      for (const line of headerLines) {
        const colon = line.indexOf(':');
        if (colon > 0) {
          const headerName = line.slice(0, colon).trim().toLowerCase();
          if (headerName === 'content-disposition') {
            disposition = line.slice(colon + 1).trim();
          }
        }
      }

      if (disposition) {
        const { name, filename } = parseContentDisposition(disposition);
        if (name) {
          if (filename !== undefined) {
            files[name] = {
              filename: filename || name,
              content: valueText,
            };
          } else {
            fields[name] = valueText;
          }
        }
      }
    }

    pos = nextPos;
  }

  return { fields, files };
}
