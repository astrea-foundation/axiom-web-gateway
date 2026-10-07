import { Identity } from 'ehbp';
/** EHBP to the attested application key. Distinct header names keep the public
 * Tinfoil shim from terminating or removing this application encryption. */
export class GatewayTransport {
  constructor(private readonly identity: Identity, private readonly origin: string) {}
  async request(input: string, init: RequestInit): Promise<Response> {
    if (new URL(input).origin !== this.origin || init.method !== 'POST' || !init.body || new Headers(init.headers).has('authorization') || new Headers(init.headers).has('cookie')) throw new Error('Encrypted gateway request required');
    const { request, context } = await this.identity.encryptRequestWithContext(new Request(input, { ...init, credentials: 'omit', referrerPolicy: 'no-referrer', redirect: 'error' }));
    if (!context) throw new Error('Encrypted gateway request required');
    const headers = new Headers(request.headers);
    const encapsulated = headers.get('ehbp-encapsulated-key');
    if (!encapsulated) throw new Error('Encrypted gateway request required');
    headers.delete('ehbp-encapsulated-key'); headers.set('axiom-encapsulated-key', encapsulated);
    const response = await fetch(new Request(request, { headers }));
    const nonce = response.headers.get('axiom-response-nonce');
    if (!response.ok || !nonce || !/^[0-9a-f]{64}$/.test(nonce) || !response.body) throw new Error('Authenticated gateway response required');
    const authenticated = new Headers(response.headers);
    authenticated.set('ehbp-response-nonce', nonce);
    return this.identity.decryptResponseWithContext(new Response(response.body, { status: response.status, headers: authenticated }), context);
  }
}
