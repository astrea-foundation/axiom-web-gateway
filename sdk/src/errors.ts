export type SessionErrorCode = 'session_capacity' | 'session_rejected' | 'session_expired' | 'session_closed';

/** Only bounded operational codes from an authenticated gateway response. */
export class GatewaySessionError extends Error {
  constructor(readonly code: SessionErrorCode, options?: ErrorOptions) {
    super(code === 'session_capacity' ? 'Gateway session capacity reached'
      : code === 'session_expired' ? 'Gateway session expired'
      : code === 'session_closed' ? 'Gateway session closed' : 'Gateway session rejected', options);
    this.name = 'GatewaySessionError';
  }
}

export class GatewayAccountError extends Error {
  constructor(cause: unknown) {
    super('Gateway account authorization failed', { cause });
    this.name = 'GatewayAccountError';
  }
}

export class GatewayRestartedError extends GatewaySessionError {
  constructor() {
    super('session_rejected');
    this.message = 'Gateway restarted; reconnect required';
    this.name = 'GatewayRestartedError';
  }
}

export function sessionRejection(code: unknown): GatewaySessionError {
  return new GatewaySessionError(code === 'session_capacity' || code === 'session_expired' || code === 'session_closed' ? code : 'session_rejected');
}

const requestStages = new Set(['request_validation','model_catalog','model_selection','trust_policy','upstream_attestation','upstream_exchange','upload_binding','capacity']);
const requestCodes = new Set(['REQUEST_FAILED','CONFIGURATION_ERROR','AUTHENTICATION_FAILED','INSUFFICIENT_CREDIT','RATE_LIMITED','TRIAL_CAPACITY','MODEL_UNAVAILABLE','CAPABILITY_MISMATCH','ATTESTATION_UNAVAILABLE','ATTESTATION_REJECTED','ATTESTATION_EXPIRED','ATTESTATION_KEY_CHANGED','PROTOCOL_UNSUPPORTED','SESSION_NOT_ACCEPTED','RECEIPT_UNAVAILABLE','INVALID_REQUEST','INVALID_RESPONSE','CANCELLED','TRANSIENT_FAILURE','STREAM_TIMEOUT','RESPONSE_TOO_LARGE','PROVIDER_DISCONNECTED']);
/** Operational metadata authenticated to this request; never provider error text. */
export class GatewayRequestError extends Error {
  constructor(readonly code: string, readonly stage?: string, readonly retryAt?: number) {
    super(code === 'RATE_LIMITED' ? 'AstreaAI is busy. Try again shortly.'
      : code === 'INSUFFICIENT_CREDIT' ? 'Insufficient balance. Top up your Axiom balance to continue.'
      : stage ? `Gateway request failed during ${stage} (${code})` : 'Gateway completion failed');
    this.name = 'GatewayRequestError';
  }
}
export function requestFailure(value: unknown): GatewayRequestError {
  const data = value && typeof value === 'object' ? value as Record<string,unknown> : {};
  const code = typeof data.code === 'string' && requestCodes.has(data.code) ? data.code : 'REQUEST_FAILED';
  const stage = typeof data.stage === 'string' && requestStages.has(data.stage) ? data.stage : undefined;
  const retryAt = typeof data.retry_at === 'number' && Number.isSafeInteger(data.retry_at) && data.retry_at > 0 ? data.retry_at : undefined;
  return new GatewayRequestError(code, stage, retryAt);
}
