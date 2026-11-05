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
