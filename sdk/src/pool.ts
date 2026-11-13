import { Identity } from 'ehbp';
import { sha256 } from '@noble/hashes/sha2.js';
import { calculateJwkThumbprint } from 'jose';
import { verifyPoolWorker } from './verifier.js';
import { POOL, CipherCommitments, base64, boundedJson, check, decoder, encoder, equivalent, fields, hash, hex, ndjson, now, outerFrames, random, requestDigest, signed, strictJson, unbase64, unhex, type SignedDocument } from './pool-wire.js';

export interface PoolOptions {
  /** Installed configuration, independent of model catalogs and attesters. */
  issuerKey: string;
  minimumWorkerPolicySequence?: number;
  rememberWorkerPolicySequence?: (sequence: number) => void;
}
export interface PoolLimits {
  context_tokens: number; output_tokens: number; input_bytes: number; output_bytes: number;
  image_pixels: number; image_steps: number; deadline: number;
}
export type PoolInput =
  | { operation: 'chat'; messages: { role: string; content: string }[]; max_tokens: number; reasoning_effort: 'low' | 'medium' | 'high'; tools: [] }
  | { operation: 'image'; prompt: string; width: number; height: number; steps: number; seed: number };
export interface PoolResult { text: string; reasoning: string; image?: Blob; usage: any; receipt: SignedDocument; binding: any }
/** Constructed by the attested GatewayClient. No account credential is exposed. */
export interface PoolChannel {
  publisherKey: string; issuerOrigin: string; publicKey: JsonWebKey; verifierWasm?: BufferSource;
  request(operation: 'reserve' | 'grants' | 'attestation' | 'exchange' | 'control', payload: unknown, signal?: AbortSignal): Promise<{ response: Response; requestId: string }>;
  sign(token: string, uri: string, workerKey: string, payload: string): Promise<string>;
  active(): void;
}
interface WorkerProof { worker: any; expires_at: number; policy_sequence: number; generation: number }
async function metadata(channel: PoolChannel, op: 'reserve' | 'grants' | 'attestation' | 'control', payload: unknown, signal?: AbortSignal): Promise<any> {
  const { response, requestId } = await channel.request(op, payload, signal);
  const chunks: Uint8Array[] = []; let total = 0;
  for await (const frame of outerFrames(response, requestId)) {
    channel.active(); check(frame.kind === 'metadata_bytes'); fields(frame.data, ['bytes_base64']);
    const chunk = unbase64(frame.data.bytes_base64, 256 * 1024); total += chunk.length; check(total <= 8 * 1024 * 1024); chunks.push(chunk);
  }
  const raw = new Uint8Array(total); let offset = 0; for (const chunk of chunks) { raw.set(chunk, offset); offset += chunk.length; }
  return strictJson(decoder.decode(raw));
}
async function attest(channel: PoolChannel, evidence: any, worker: any, challenge: string, minimum: number, signal?: AbortSignal): Promise<WorkerProof> {
  fields(worker, ['worker_id', 'boot_id', 'encryption_key', 'identity_key', 'model_manifest', 'logical_origin', 'evidence_profile', 'deployment_digest']);
  unhex(worker.worker_id, 16); for (const field of ['boot_id', 'encryption_key', 'identity_key', 'model_manifest', 'deployment_digest']) unhex(worker[field], 32);
  const origin = new URL(worker.logical_origin); check(origin.protocol === 'https:' && origin.origin === worker.logical_origin && !origin.username && !origin.password);
  check(worker.evidence_profile === 'tinfoil-gpu-v3' && evidence.protocol === POOL && evidence.challenge === challenge);
  const decoded = strictJson(decoder.decode(unbase64(evidence.document.device_evidence, 4 * 1024 * 1024)));
  check(Array.isArray(decoded.items) && decoded.items.length === 1);
  const init: RequestInit = { credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer', signal: AbortSignal.any([AbortSignal.timeout(60_000), ...(signal ? [signal] : [])]) };
  const jwks = await boundedJson(await fetch('https://nras.attestation.nvidia.com/.well-known/jwks.json', init), 2 * 1024 * 1024);
  const nvidia = [];
  for (const device of decoded.items) {
    check(device.kind === 'gpu' && device.vendor === 'nvidia' && device.format === 'https://tinfoil.sh/format/nvidia-gpu-evidence/v1');
    const payload = typeof device.evidence === 'string' ? strictJson(device.evidence) : device.evidence;
    check(payload.nonce === challenge);
    const verdict = await boundedJson(await fetch('https://nras.attestation.nvidia.com/v3/attest/gpu', { ...init, method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) }), 2 * 1024 * 1024);
    check(Array.isArray(verdict) && verdict.length === 2 && verdict[0]?.[0] === 'JWT' && verdict[1] && typeof verdict[1] === 'object' && !Array.isArray(verdict[1]) && Object.keys(verdict[1]).length === 1);
    const jwt = verdict[0][1]; check(typeof jwt === 'string');
    nvidia.push({ device_id: device.id, jwt, jwks, detached: verdict[1] });
  }
  const proof = strictJson(await verifyPoolWorker(evidence, { challenge, origin: worker.logical_origin, publisher_key: channel.publisherKey, model_manifest: worker.model_manifest, now: now(), minimum_policy_sequence: minimum }, nvidia, channel.verifierWasm));
  check(equivalent(proof.worker, worker) && proof.expires_at > now() && proof.expires_at <= now() + 240 && proof.policy_sequence >= minimum && proof.generation > 0);
  return proof;
}
export class PoolClient {
  private minimum: number;
  constructor(private readonly channel: PoolChannel, private readonly options: PoolOptions) { unhex(options.issuerKey, 32); this.minimum = options.minimumWorkerPolicySequence ?? 0; }
  async run(model: string, input: PoolInput, limits: PoolLimits, onProvisional: (frame: any) => void = () => {}, options: { signal?: AbortSignal; requestId?: string } = {}): Promise<PoolResult> {
    const channel = this.channel; channel.active(); unhex(model, 32);
    const requestId = options.requestId ?? random(16); unhex(requestId, 16);
    const challenge = random(32); const jkt = await calculateJwkThumbprint(channel.publicKey, 'sha256');
    const reserved = await metadata(channel, 'reserve', { request_id: requestId, model_manifest: model, operation: input.operation, limits, client_key: channel.publicKey, challenge }, options.signal);
    const ticket = await signed(reserved.ticket, this.options.issuerKey, 'axiom-pool-ticket-v1');
    const binding = ticket.binding;
    check(ticket.protocol === POOL && ticket.expires_at > now() && binding.request_id === requestId && binding.reservation_id === reserved.reservation_id && binding.client_jkt === jkt && binding.worker.model_manifest === model && binding.operation === input.operation && equivalent(binding.limits, limits));
    let proof = await attest(channel, reserved.evidence, binding.worker, challenge, this.minimum, options.signal);
    this.minimum = Math.max(this.minimum, proof.policy_sequence); this.options.rememberWorkerPolicySequence?.(this.minimum);
    const issued = await metadata(channel, 'grants', { reservation_id: binding.reservation_id }, options.signal);
    const grant = await signed(issued.grant, this.options.issuerKey, 'axiom-pool-grant-v1');
    check(grant.protocol === POOL && grant.issuer === channel.issuerOrigin && grant.audience === 'axiom-pool-worker-v1' && grant.expires_at > now() && grant.issued_at <= now() + 30 && grant.expires_at - grant.issued_at <= 120 && equivalent(grant.binding, binding));
    check(grant.price_version === 'pool-free-preview-v1' && grant.max_charge_microusd === 0, 'Pool price has not been accepted');
    const bindingBytes = JSON.stringify(binding); const payload = JSON.stringify({ binding: bindingBytes, input }); const token = JSON.stringify(issued.grant);
    const authorization = await channel.sign(token, binding.worker.logical_origin + '/v1/exchange', binding.worker.encryption_key, payload);
    const config = new Uint8Array(41); config.set([0, 0, 32]); config.set(unhex(binding.worker.encryption_key, 32), 3); config.set([0, 4, 0, 1, 0, 2], 35);
    const identity = await Identity.unmarshalPublicConfig(config);
    const encrypted = await identity.encryptRequestWithContext(new Request(binding.worker.logical_origin + '/v1/exchange', { method: 'POST', body: JSON.stringify({ protocol: POOL, grant: token, proof: authorization, payload }), ...(options.signal ? { signal: options.signal } : {}) }));
    check(encrypted.context); const enc = encrypted.request.headers.get('ehbp-encapsulated-key'); check(enc);
    const body = new Uint8Array(await encrypted.request.arrayBuffer()); const requestHash = requestDigest(enc, body);
    const outer = await channel.request('exchange', { reservation_id: binding.reservation_id, ticket: reserved.ticket, sealed: { encapsulated_key: enc, body: base64(body) } }, options.signal);
    const frames = outerFrames(outer.response, outer.requestId); const first = await frames.next(); check(!first.done && first.value.kind === 'worker_meta'); fields(first.value.data, ['response_nonce']);
    const nonce = first.value.data.response_nonce; unhex(nonce, 32); const commitments = new CipherCommitments(requestHash, nonce);
    let finished = false;
    const wire = new ReadableStream<Uint8Array>({
      async pull(controller) {
        try {
          channel.active(); const next = await frames.next();
          if (next.done) { finished = true; controller.close(); return; }
          check(next.value.kind === 'worker_bytes'); fields(next.value.data, ['bytes_base64']); const raw = unbase64(next.value.data.bytes_base64, 256 * 1024); commitments.push(raw); controller.enqueue(raw);
        } catch (error) { controller.error(error); }
      },
      async cancel() { await frames.return(undefined).catch(() => {}); },
    });
    const response = await identity.decryptResponseWithContext(new Response(wire, { headers: { 'ehbp-response-nonce': nonce } }), encrypted.context);
    check(response.body); const transcript = sha256.create(); const bindingHash = hash(bindingBytes);
    let sequence = 0; let terminal: any; let text = ''; let reasoning = ''; const image: Uint8Array[] = []; let imageInfo: any; let imageBytes = 0; let imageChunks = 0; const imageHash = sha256.create();
    try {
      for await (const opened of ndjson(response.body, limits.output_bytes)) {
        channel.active();
        if (proof.expires_at <= now() + 30) {
          const fresh = random(32); const evidence = await metadata(channel, 'attestation', { reservation_id: binding.reservation_id, challenge: fresh }, options.signal);
          proof = await attest(channel, evidence, binding.worker, fresh, this.minimum, options.signal); this.minimum = Math.max(this.minimum, proof.policy_sequence); this.options.rememberWorkerPolicySequence?.(this.minimum);
        }
        check(proof.expires_at > now());
        const frame = opened.value; fields(frame, ['protocol', 'binding_sha256', 'request_wire_sha256', 'sequence', 'kind', 'data']);
        check(!terminal && frame.protocol === POOL && frame.binding_sha256 === bindingHash && frame.request_wire_sha256 === requestHash && frame.sequence === sequence && sequence < 65536);
        const prefix = commitments.take(sequence);
        if (frame.kind === 'terminal') {
          const data = frame.data; fields(data, ['success', 'transcript_sha256', 'frame_count', 'finish_reason', 'usage', 'receipt']);
          check(data.success === true && data.frame_count === sequence && data.transcript_sha256 === hex(transcript.digest()) && ['stop', 'length'].includes(data.finish_reason));
          const receipt = await signed(data.receipt, binding.worker.identity_key, 'axiom-pool-receipt-v1');
          check(receipt.protocol === POOL && equivalent(receipt.binding, binding) && receipt.binding_sha256 === bindingHash && receipt.request_wire_sha256 === requestHash && receipt.response_prefix_sha256 === prefix && receipt.status === 'succeeded' && equivalent(receipt.usage, data.usage) && receipt.price_version === grant.price_version && receipt.charge_microusd === 0);
          fields(data.usage, ['input_tokens', 'output_tokens', 'image_pixels', 'image_steps']); for (const value of Object.values(data.usage)) check(Number.isSafeInteger(value) && (value as number) >= 0);
          check(data.usage.input_tokens + data.usage.output_tokens <= limits.context_tokens && data.usage.output_tokens <= limits.output_tokens && data.usage.image_pixels <= limits.image_pixels && data.usage.image_steps <= limits.image_steps);
          terminal = data; continue;
        }
        switch (frame.kind) {
          case 'accepted': check(sequence === 0); break;
          case 'text_delta': case 'reasoning_delta':
            fields(frame.data, ['text', 'provisional']); check(input.operation === 'chat' && typeof frame.data.text === 'string' && frame.data.provisional === true);
            if (frame.kind === 'text_delta') text += frame.data.text; else reasoning += frame.data.text; break;
          case 'image_manifest':
            check(input.operation === 'image' && !imageInfo); imageInfo = frame.data; fields(imageInfo, ['artifact_id', 'media_type', 'bytes', 'width', 'height', 'chunks', 'sha256']); unhex(imageInfo.artifact_id, 16); unhex(imageInfo.sha256, 32);
            check(imageInfo.media_type === 'image/png' && Number.isSafeInteger(imageInfo.bytes) && imageInfo.bytes > 0 && imageInfo.bytes <= 64 * 1024 * 1024 && Number.isSafeInteger(imageInfo.width) && Number.isSafeInteger(imageInfo.height) && imageInfo.width > 0 && imageInfo.height > 0 && imageInfo.width * imageInfo.height <= limits.image_pixels && Number.isSafeInteger(imageInfo.chunks) && imageInfo.chunks > 0 && imageInfo.chunks <= 1024); break;
          case 'image_chunk': {
            fields(frame.data, ['artifact_id', 'index', 'bytes_base64']); check(imageInfo && frame.data.artifact_id === imageInfo.artifact_id && frame.data.index === imageChunks++ && imageChunks <= imageInfo.chunks);
            const chunk = unbase64(frame.data.bytes_base64, 256 * 1024); imageBytes += chunk.length; check(chunk.length > 0 && imageBytes <= imageInfo.bytes); imageHash.update(chunk); image.push(chunk); break;
          }
          case 'heartbeat': fields(frame.data, ['provisional']); check(frame.data.provisional === true); break;
          case 'usage': fields(frame.data, ['input_tokens', 'output_tokens', 'image_pixels', 'image_steps']); break;
          default: check(false, 'Unsupported worker frame or authenticated failure');
        }
        transcript.update(opened.raw); sequence++; onProvisional(frame);
      }
      check(terminal && finished && proof.expires_at > now(), 'Worker completion, fresh proof or relay EOF missing'); commitments.finish();
      if (input.operation === 'image') {
        check(imageInfo && imageBytes === imageInfo.bytes && imageChunks === imageInfo.chunks && hex(imageHash.digest()) === imageInfo.sha256);
        const header = new Uint8Array(24); let at = 0; for (const chunk of image) { const take = Math.min(chunk.length, 24 - at); header.set(chunk.subarray(0, take), at); at += take; if (at === 24) break; }
        check(hex(header.subarray(0, 8)) === '89504e470d0a1a0a' && new DataView(header.buffer).getUint32(16) === imageInfo.width && new DataView(header.buffer).getUint32(20) === imageInfo.height);
      }
      channel.active(); return { text, reasoning, ...(imageInfo ? { image: new Blob(image as BlobPart[], { type: 'image/png' }) } : {}), usage: terminal.usage, receipt: terminal.receipt, binding };
    } catch {
      await frames.return(undefined).catch(() => {});
      void metadata(channel, 'control', { reservation_id: binding.reservation_id, action: 'cancel' }).catch(() => {});
      throw new Error('Pool response incomplete or unauthenticated; inference was not replayed');
    }
  }
}
