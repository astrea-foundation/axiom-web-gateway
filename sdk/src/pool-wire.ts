import { sha256 } from '@noble/hashes/sha2.js';

export const POOL = 'axiom-pool-e2ee-v1';
export const OUTER = 'axiom-gateway-pool-v1';
export const encoder = new TextEncoder();
export const decoder = new TextDecoder('utf-8', { fatal: true });
export const hex = (bytes: Uint8Array) => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
export const hash = (bytes: Uint8Array | string) => hex(sha256(typeof bytes === 'string' ? encoder.encode(bytes) : bytes));
export const random = (bytes: number) => hex(crypto.getRandomValues(new Uint8Array(bytes)));
export const now = () => Math.floor(Date.now() / 1000);
export function fail(message = 'Pool authentication failed'): never { throw new Error(message); }
export function check(value: unknown, message?: string): asserts value { if (!value) fail(message); }
export function unhex(value: string, length: number): Uint8Array<ArrayBuffer> {
  check(new RegExp(`^[0-9a-f]{${length * 2}}$`).test(value));
  return Uint8Array.from(value.match(/../g)!, h => parseInt(h, 16));
}
export function base64(bytes: Uint8Array): string {
  let out = ''; for (let offset = 0; offset < bytes.length; offset += 8192) out += String.fromCharCode(...bytes.subarray(offset, offset + 8192));
  return btoa(out);
}
export function unbase64(value: string, limit: number, url = false): Uint8Array<ArrayBuffer> {
  check(typeof value === 'string' && value.length <= limit);
  check((url ? /^[A-Za-z0-9_-]*$/ : /^[A-Za-z0-9+/]*={0,2}$/).test(value));
  const standard = url ? value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - value.length % 4) % 4) : value;
  const bytes = Uint8Array.from(atob(standard), c => c.charCodeAt(0));
  check((url ? base64(bytes).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '') : base64(bytes)) === value);
  return bytes;
}
export function fields(value: any, names: string[]): void {
  check(value && typeof value === 'object' && !Array.isArray(value));
  check(Object.keys(value).sort().join('|') === [...names].sort().join('|'));
}
export function equivalent(a: unknown, b: unknown): boolean {
  const canonical = (value: any): any => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(k => [k, canonical(value[k])])) : value;
  return JSON.stringify(canonical(a)) === JSON.stringify(canonical(b));
}
/** JSON.parse alone silently accepts duplicate identity fields. */
export function strictJson(raw: string): any {
  let i = 0;
  const ws = () => { while (i < raw.length && /[\x20\t\r\n]/.test(raw[i]!)) i++; };
  const string = () => {
    check(raw[i] === '"'); const start = i++;
    for (; i < raw.length; i++) {
      if (raw[i] === '\\') { i++; continue; }
      if (raw[i] === '"') {
        const value = JSON.parse(raw.slice(start, ++i));
        for (let p = 0; p < value.length; p++) {
          const code = value.charCodeAt(p);
          if (code >= 0xd800 && code <= 0xdbff) { const next = value.charCodeAt(++p); check(next >= 0xdc00 && next <= 0xdfff); }
          else check(code < 0xdc00 || code > 0xdfff);
        }
        return value as string;
      }
    }
    return fail('Incomplete JSON string');
  };
  const consume = (depth: number): void => {
    check(depth <= 64); ws();
    if (raw[i] === '"') { string(); return; }
    if (raw[i] === '{') {
      i++; ws(); const seen = new Set<string>();
      if (raw[i] !== '}') for (;;) {
        ws(); const key = string(); check(!seen.has(key), 'Duplicate JSON key'); seen.add(key);
        ws(); check(raw[i++] === ':'); consume(depth + 1); ws();
        if (raw[i] !== ',') break; i++;
      }
      check(raw[i++] === '}'); return;
    }
    if (raw[i] === '[') {
      i++; ws(); if (raw[i] !== ']') for (;;) { consume(depth + 1); ws(); if (raw[i] !== ',') break; i++; }
      check(raw[i++] === ']'); return;
    }
    const match = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(raw.slice(i));
    check(match); if (!['true', 'false', 'null'].includes(match[0])) check(Number.isFinite(Number(match[0]))); i += match[0].length;
  };
  consume(0); ws(); check(i === raw.length); return JSON.parse(raw);
}
export interface SignedDocument { payload: string; signature: string }
export async function signed(doc: SignedDocument, key: string, domain: string): Promise<any> {
  fields(doc, ['payload', 'signature']);
  const raw = unbase64(doc.payload, 180 * 1024, true);
  const prefix = encoder.encode(domain + '\0'); const message = new Uint8Array(prefix.length + raw.length); message.set(prefix); message.set(raw, prefix.length);
  const publicKey = await crypto.subtle.importKey('raw', unhex(key, 32), 'Ed25519', false, ['verify']);
  check(await crypto.subtle.verify('Ed25519', publicKey, unhex(doc.signature, 64), message), 'Invalid signed pool document');
  return strictJson(decoder.decode(raw));
}
export async function boundedJson(response: Response, limit: number): Promise<any> {
  check(response.ok && response.body); const reader = response.body.getReader(); let total = 0; const chunks: Uint8Array[] = [];
  try { for (;;) { const next = await reader.read(); if (next.done) break; total += next.value.length; check(total <= limit); chunks.push(next.value); } }
  catch (error) { await reader.cancel().catch(() => {}); throw error; } finally { reader.releaseLock(); }
  const raw = new Uint8Array(total); let at = 0; for (const chunk of chunks) { raw.set(chunk, at); at += chunk.length; }
  return strictJson(decoder.decode(raw));
}
export async function* ndjson(body: ReadableStream<Uint8Array>, maxBytes: number): AsyncGenerator<{ value: any; raw: Uint8Array }> {
  const reader = body.getReader(); let pending = new Uint8Array(0); let total = 0; let ended = false;
  try {
    for (;;) {
      const next = await reader.read(); if (next.done) { ended = true; break; }
      total += next.value.length; check(total <= maxBytes, 'Pool response limit');
      // Consume small slices even if a transport coalesces many frames.
      for (let offset = 0; offset < next.value.length; offset += 64 * 1024) {
        const chunk = next.value.subarray(offset, offset + 64 * 1024);
        const joined = new Uint8Array(pending.length + chunk.length); joined.set(pending); joined.set(chunk, pending.length); pending = joined;
        let start = 0;
        for (;;) { const end = pending.indexOf(10, start); if (end < 0) break; check(end - start <= 1024 * 1024); const raw = pending.slice(start, end + 1); start = end + 1; yield { value: strictJson(decoder.decode(raw)), raw }; }
        pending = pending.slice(start); check(pending.length <= 1024 * 1024);
      }
    }
    check(pending.length === 0, 'Truncated pool frame');
  } finally { if (!ended) await reader.cancel().catch(() => {}); reader.releaseLock(); }
}
export async function* outerFrames(response: Response, requestId: string): AsyncGenerator<any> {
  check(response.ok && response.body); let sequence = 0; let terminal = false; const transcript = sha256.create();
  for await (const { value, raw } of ndjson(response.body, 160 * 1024 * 1024)) {
    fields(value, ['protocol', 'request_id', 'sequence', 'kind', 'data']);
    check(!terminal && value.protocol === OUTER && value.request_id === requestId && value.sequence === sequence++ && sequence <= 65536);
    if (value.kind === 'terminal') { fields(value.data, ['success', 'transcript_sha256']); check(value.data.success === true && value.data.transcript_sha256 === hex(transcript.digest()), 'Gateway relay incomplete'); terminal = true; }
    else { check(['metadata_bytes', 'worker_meta', 'worker_bytes'].includes(value.kind)); transcript.update(raw); yield value; }
  }
  check(terminal, 'Gateway relay truncated');
}
/** Digest of the exact decoded inner request, independent of proxy encoding. */
export function requestDigest(enc: string, body: Uint8Array): string {
  const hash = sha256.create(); hash.update(encoder.encode('axiom-pool-wire-v1\0'));
  const length = new Uint8Array(4); new DataView(length.buffer).setUint32(0, 32); hash.update(length); hash.update(unhex(enc, 32));
  const size = new Uint8Array(8); new DataView(size.buffer).setBigUint64(0, BigInt(body.length)); hash.update(size); hash.update(body); return hex(hash.digest());
}
/** Track ciphertext commitments without copying response secrets or full bodies. */
export class CipherCommitments {
  private readonly hash = sha256.create(); private pending = new Uint8Array(0); private sequence = 0; private total = 0;
  private readonly before = new Map<number, string>();
  constructor(request: string, nonce: string) { this.hash.update(encoder.encode('axiom-pool-response-prefix-v1\0')); this.hash.update(unhex(request, 32)); this.hash.update(unhex(nonce, 32)); }
  push(raw: Uint8Array): void {
    this.total += raw.length; check(this.total <= 100 * 1024 * 1024);
    for (let offset = 0; offset < raw.length; offset += 64 * 1024) {
      const chunk = raw.subarray(offset, offset + 64 * 1024); const joined = new Uint8Array(this.pending.length + chunk.length); joined.set(this.pending); joined.set(chunk, this.pending.length); this.pending = joined;
      let at = 0;
      while (this.pending.length - at >= 4) {
        const size = new DataView(this.pending.buffer, this.pending.byteOffset + at).getUint32(0);
        check(size >= 16 && size <= 1024 * 1024 + 16); if (this.pending.length - at < size + 4) break;
        check(this.sequence < 65536); this.before.set(this.sequence++, hex(this.hash.clone().digest())); this.hash.update(this.pending.subarray(at, at + size + 4)); at += size + 4;
      }
      this.pending = this.pending.slice(at); check(this.pending.length <= 1024 * 1024 + 20);
    }
  }
  take(sequence: number): string { const value = this.before.get(sequence); check(value); this.before.delete(sequence); return value; }
  finish(): void { check(this.pending.length === 0 && this.before.size === 0 && this.sequence > 0, 'Truncated or mismatched encrypted framing'); }
}
