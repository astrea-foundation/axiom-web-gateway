// Public interop fixture only. No listener or plaintext inference mode.
import { createInterface } from 'node:readline';
import { Identity } from 'ehbp';
import { GatewayTransport } from '../dist/transport.js';
const lines = createInterface({ input: process.stdin })[Symbol.asyncIterator]();
const identity = await Identity.fromPublicKeyHex(process.argv[2]);
globalThis.fetch = async request => {
  if (request.headers.has('ehbp-encapsulated-key')) throw new Error('Shim would intercept application encryption');
  console.log(JSON.stringify({ encapsulated: request.headers.get('axiom-encapsulated-key'), body: Buffer.from(await request.arrayBuffer()).toString('hex') }));
  const { value } = await lines.next();
  const sealed = JSON.parse(value);
  return new Response(Buffer.from(sealed.body, 'hex'), { headers: { 'axiom-response-nonce': sealed.nonce } });
};
const response = await new GatewayTransport(identity, 'https://gateway.example').request('https://gateway.example/v1/rpc', { method: 'POST', body: 'public interoperability fixture', credentials: 'omit' });
if (await response.text() !== '{"interoperable":true}\n') throw new Error('Interoperability mismatch');
process.exit(0);
