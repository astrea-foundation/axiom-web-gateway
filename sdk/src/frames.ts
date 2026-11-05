import { sha256 } from '@noble/hashes/sha2.js';
import { GatewaySessionError, sessionRejection } from './errors.js';

export const PROTOCOL = 'axiom-gateway-v2';
const MAX_FRAME = 1024 * 1024;
const MAX_RESPONSE = 16 * 1024 * 1024;
const hex = (bytes: Uint8Array) => Array.from(bytes, v => v.toString(16).padStart(2, '0')).join('');

export interface Frame {
  protocol: typeof PROTOCOL;
  request_id: string;
  sequence: number;
  kind: string;
  data: unknown;
}
export interface Terminal { success: true; transcript_sha256: string; result: unknown }

/** Input must already be AEAD-authenticated by EHBP. Deltas remain provisional;
 * success is returned only after terminal binding AND authenticated EOF. */
export async function readFrames(
  stream: ReadableStream<Uint8Array>, requestId: string,
  onProvisional: (frame: Frame) => void,
): Promise<Terminal> {
  const reader = stream.getReader();
  const decoder = new TextDecoder('utf-8', { fatal: true });
  const digest = sha256.create();
  let pending = new Uint8Array(0);
  let total = 0, sequence = 0;
  let terminal: Terminal | undefined;
  let rejected: GatewaySessionError | undefined;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_RESPONSE) throw new Error('Gateway response exceeds limit');
      const joined = new Uint8Array(pending.length + value.length);
      joined.set(pending); joined.set(value, pending.length);
      let start = 0;
      for (let end = 0; end < joined.length; end++) {
        if (joined[end] !== 10) continue;
        if (end - start > MAX_FRAME || terminal || rejected) throw new Error('Invalid gateway framing');
        const line = joined.subarray(start, end + 1);
        const frame = JSON.parse(decoder.decode(line)) as Frame;
        // RPC admission failures are encrypted to this exact EHBP request.
        // They never contain model output or authorize a successful completion.
        if (sequence === 0 && Object.keys(frame).length === 2 && (frame as unknown as { success?: boolean }).success === false && Object.hasOwn(frame, 'code')) {
          rejected = sessionRejection((frame as unknown as { code: unknown }).code);
          start = end + 1;
          continue;
        }
        if (frame.protocol !== PROTOCOL || frame.request_id !== requestId || frame.sequence !== sequence++ ||
            typeof frame.kind !== 'string' || !Object.hasOwn(frame, 'data')) throw new Error('Gateway stream binding failed');
        if (frame.kind === 'terminal') {
          const data = frame.data as Terminal;
          if (data?.success !== true || data.transcript_sha256 !== hex(digest.digest())) throw new Error('Gateway completion failed');
          terminal = data;
        } else {
          digest.update(line);
          onProvisional(frame);
        }
        start = end + 1;
      }
      pending = joined.slice(start);
      if (pending.length > MAX_FRAME) throw new Error('Gateway frame exceeds limit');
    }
    if (pending.length) throw new Error('Gateway stream was interrupted');
    if (rejected) throw rejected;
    if (!terminal) throw new Error('Gateway stream was interrupted');
    return terminal;
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  } finally { reader.releaseLock(); }
}
