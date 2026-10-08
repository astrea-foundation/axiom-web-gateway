import { Identity } from 'ehbp';
import { GatewayTransport } from './transport.js';
import { verifyGateway } from './verifier.js';
import { SignJWT } from 'jose';
import { sha256 } from '@noble/hashes/sha2.js';
import { PROTOCOL, readFrames, type Frame } from './frames.js';
import { delegationDeadline } from './expiry.js';
export { type Frame } from './frames.js';

const encoder = new TextEncoder();
const hex = (bytes: Uint8Array) => Array.from(bytes, v => v.toString(16).padStart(2, '0')).join('');
const random = (length: number) => hex(crypto.getRandomValues(new Uint8Array(length)));
const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
const now = () => Math.floor(Date.now() / 1000);
function origin(value: string): string {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.origin !== value || url.username || url.password) throw new Error('An HTTPS origin is required');
  return value;
}
async function boundedJson(response: Response, limit: number): Promise<any> {
  if (!response.ok || !response.body) throw new Error('Gateway request failed');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = []; let length = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read(); if (done) break;
      length += value.length;
      if (length > limit) throw new Error('Gateway response exceeds limit');
      chunks.push(value);
    }
    const joined = new Uint8Array(length); let offset = 0;
    for (const chunk of chunks) { joined.set(chunk, offset); offset += chunk.length; }
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(joined));
  } catch (error) { await reader.cancel().catch(() => {}); throw error; }
  finally { reader.releaseLock(); }
}

export interface VerifiedGateway {
  encryption_key: string; authorization_key: string; origin: string; image_digest: string;
  source_repository: string; source_revision: string; generation: number;
  policy_sequence: number; policy_expires_at: number; evidence_expires_at: number;
  config_repository: string; config_digest: string;
}
export interface GatewayOptions {
  /** Installed application's pinned build publisher key, never supplied by the attester. */
  publisherKey: string;
  gatewayOrigin: string;
  backendOrigin: string;
  /** Persist this independently of gateway responses to prevent policy rollback. */
  minimumPolicySequence?: number;
  rememberPolicySequence?: (sequence: number) => void;
  /** Allows extension cookie/session integration without putting credentials in proofs. */
  grant: (publicKey: JsonWebKey, signal?: AbortSignal) => Promise<string>;
  /** Optional packaged WASM bytes for extensions that prohibit fetched executable code. */
  verifierWasm?: BufferSource;
}

async function attest(options: GatewayOptions, signal?: AbortSignal, minimumSequence = options.minimumPolicySequence ?? 0): Promise<VerifiedGateway> {
  const deadline = AbortSignal.any([AbortSignal.timeout(60_000), ...(signal ? [signal] : [])]);
    const challenge = random(32);
    const common: RequestInit = { credentials: 'omit', referrerPolicy: 'no-referrer', redirect: 'error', signal: deadline };
    const [evidence, policy] = await Promise.all([
      fetch(options.gatewayOrigin + '/v1/attestation', { ...common, method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ challenge }) }).then(r => boundedJson(r, 8 * 1024 * 1024)),
      fetch(options.backendOrigin + '/api/v1/web-gateway/trust-policy', common).then(r => boundedJson(r, 128 * 1024)),
    ]);
    // Current policy comes from the relying application's backend, not the attester.
    evidence.policy = policy;
    const proof = JSON.parse(await verifyGateway(evidence, {
      challenge, origin: options.gatewayOrigin, publisher_key: options.publisherKey,
      now: now(), minimum_policy_sequence: minimumSequence,
    }, options.verifierWasm)) as VerifiedGateway;
    options.rememberPolicySequence?.(proof.policy_sequence);
  return proof;
}

export class GatewayClient {
  readonly proof: VerifiedGateway;
  private constructor(
    private readonly options: GatewayOptions, proof: VerifiedGateway,
    private readonly transport: GatewayTransport, private readonly key: CryptoKey,
    private readonly publicKey: JsonWebKey, private readonly session: string,
    private readonly expires: number,
  ) { this.proof = proof; }

  static async connect(options: GatewayOptions, signal?: AbortSignal): Promise<GatewayClient> {
    origin(options.gatewayOrigin); origin(options.backendOrigin);
    if (!/^[0-9a-f]{64}$/.test(options.publisherKey)) throw new Error('Invalid pinned publisher key');
    const deadline = AbortSignal.any([AbortSignal.timeout(60_000), ...(signal ? [signal] : [])]);
    const proof = await attest(options, deadline);
    const configuration = new Uint8Array(41);
    configuration.set([0, 0, 32]);
    configuration.set(Uint8Array.from(proof.encryption_key.match(/../g)!, h => parseInt(h, 16)), 3);
    configuration.set([0, 4, 0, 1, 0, 2], 35);
    // Only a locally verified key reaches the upstream EHBP implementation.
    const identity = await Identity.unmarshalPublicConfig(configuration);
    const transport = new GatewayTransport(identity, options.gatewayOrigin);
    const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
    const exported = await crypto.subtle.exportKey('jwk', keys.publicKey);
    const publicKey: JsonWebKey = { kty: 'EC', crv: 'P-256', x: exported.x!, y: exported.y! };
    const grant = await options.grant(publicKey, deadline);
    if (!/^axw_[A-Za-z0-9_-]{43}$/.test(grant)) throw new Error('Invalid gateway grant');
    const payload = JSON.stringify({ grant });
    const authorization = await GatewayClient.authorize(keys.privateKey, publicKey, grant, options.gatewayOrigin + '/v1/session', proof.encryption_key, payload);
    const response = await transport.request(options.gatewayOrigin + '/v1/session', {
      method: 'POST', body: JSON.stringify({ protocol: PROTOCOL, session_id: null, proof: authorization, payload }),
      credentials: 'omit', referrerPolicy: 'no-referrer', redirect: 'error', signal: deadline,
    });
    GatewayClient.encrypted(response);
    const value = await boundedJson(response, 16_384);
    if (value.success !== true || value.data?.protocol !== PROTOCOL || !/^[0-9a-f]{64}$/.test(value.data?.session_id) ||
        !Number.isSafeInteger(value.data?.expires_at)) throw new Error('Gateway session rejected');
    const expires = delegationDeadline(value.data.expires_at, now(), 900);
    return new GatewayClient(options, proof, transport, keys.privateKey, publicKey, value.data.session_id, expires);
  }

  private static encrypted(response: Response): void {
    if (!response.ok || !/^[0-9a-f]{64}$/.test(response.headers.get('ehbp-response-nonce') ?? '') || !response.body) throw new Error('Authenticated gateway response required');
  }
  private static authorize(key: CryptoKey, publicKey: JsonWebKey, token: string, uri: string, gatewayKey: string, payload: string): Promise<string> {
    return new SignJWT({ htm: 'POST', htu: uri, iat: now(), jti: random(16), ath: b64(sha256(encoder.encode(token))), gateway_key: gatewayKey, request_digest: hex(sha256(encoder.encode(payload))) })
      .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: publicKey }).sign(key);
  }

  /** Upload original bytes through attested EHBP; handles bind the session, model and next request. */
  async upload(input: { bytes: Uint8Array; targetRequestId: string; model: string; kind: 'image' | 'file'; name: string; mimeType: string }, signal?: AbortSignal): Promise<string> {
    if (!input.bytes.length || input.bytes.length > (input.kind === 'image' ? 5 : 10) * 1024 * 1024) throw new Error('Attachment exceeds limit');
    const options = signal ? { signal } : {};
    try {
      const result = await this.rpc({ op: 'upload_begin', upload: { target_request_id: input.targetRequestId, model: input.model, kind: input.kind, name: input.name, mime_type: input.mimeType, length: input.bytes.length, sha256: hex(sha256(input.bytes)) } }, undefined, options) as { upload_id?: string };
      if (!/^[0-9a-f]{32}$/.test(result.upload_id ?? '')) throw new Error('Invalid upload handle');
      const uploadId = result.upload_id!;
      for (let offset = 0; offset < input.bytes.length; offset += 256 * 1024) {
        const bytes = input.bytes.subarray(offset, offset + 256 * 1024);
        let binary = '';
        for (let at = 0; at < bytes.length; at += 16384) binary += String.fromCharCode(...bytes.subarray(at, at + 16384));
        await this.rpc({ op: 'upload_chunk', upload_id: uploadId, offset, data: btoa(binary), final_chunk: offset + bytes.length === input.bytes.length }, undefined, options);
      }
      return uploadId;
    } catch (error) {
      await this.rpc({ op: 'upload_abort', target_request_id: input.targetRequestId }).catch(() => {});
      throw error;
    }
  }
  async rpc(operation: { op: 'models' } | { op: 'infer'; request: Record<string, unknown>; uploads?: Array<{ upload_id: string; message_index: number }> } | { op: 'cancel'; target_request_id: string }
    | { op: 'upload_begin'; upload: { target_request_id: string; model: string; kind: 'image' | 'file'; name: string; mime_type: string; length: number; sha256: string } }
    | { op: 'upload_chunk'; upload_id: string; offset: number; data: string; final_chunk: boolean } | { op: 'upload_abort'; target_request_id: string },
    onProvisional: (frame: Frame) => void = () => {}, options: { signal?: AbortSignal; requestId?: string } = {}): Promise<unknown> {
    if (this.expires <= now() || this.proof.policy_expires_at <= now()) throw new Error('Gateway session expired');
    if (this.proof.evidence_expires_at <= now() + 30) {
      const fresh = await attest(this.options, options.signal, this.proof.policy_sequence);
      if (fresh.encryption_key !== this.proof.encryption_key || fresh.authorization_key !== this.proof.authorization_key) throw new Error('Gateway restarted; reconnect required');
      Object.assign(this.proof, fresh);
    }
    const requestId = options.requestId ?? random(16);
    if (!/^[0-9a-f]{32}$/.test(requestId)) throw new Error('Invalid request identity');
    const payload = JSON.stringify({ request_id: requestId, ...operation });
    if (encoder.encode(payload).length > 3 * 1024 * 1024) throw new Error('Gateway request exceeds limit');
    const proof = await GatewayClient.authorize(this.key, this.publicKey, this.session, this.options.gatewayOrigin + '/v1/rpc', this.proof.encryption_key, payload);
    const response = await this.transport.request(this.options.gatewayOrigin + '/v1/rpc', {
      method: 'POST', body: JSON.stringify({ protocol: PROTOCOL, session_id: this.session, proof, payload }),
      credentials: 'omit', referrerPolicy: 'no-referrer', redirect: 'error',
      signal: AbortSignal.any([AbortSignal.timeout(610_000), ...(options.signal ? [options.signal] : [])]),
    });
    GatewayClient.encrypted(response);
    return (await readFrames(response.body!, requestId, onProvisional)).result;
  }
}

/** Uses existing HttpOnly account session + CSRF; account credentials never go to the gateway. */
export function browserGrant(backendOrigin: string, csrf?: () => string): GatewayOptions['grant'] {
  origin(backendOrigin);
  return async (publicKey, signal) => {
    // The existing session endpoint returns CSRF for approved first-party
    // origins, including a chat origin that cannot read the API host's cookie.
    const csrfToken = csrf ? csrf() : (await boundedJson(await fetch(backendOrigin + '/api/v1/auth/session', {
      credentials: 'include', referrerPolicy: 'no-referrer', redirect: 'error', ...(signal ? { signal } : {}),
    }), 16_384)).csrf_token;
    if (typeof csrfToken !== 'string' || csrfToken.length === 0 || csrfToken.length > 512) throw new Error('An authenticated account session is required');
    const value = await boundedJson(await fetch(backendOrigin + '/api/v1/web-gateway/grants', {
      method: 'POST', credentials: 'include', referrerPolicy: 'no-referrer', redirect: 'error',
      headers: { 'content-type': 'application/json', 'x-csrf-token': csrfToken }, body: JSON.stringify({ browser_key: publicKey }),
      ...(signal ? { signal } : {}),
    }), 16_384);
    return value.grant;
  };
}
