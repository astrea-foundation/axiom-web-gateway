// Public test fixture exchange only. No network listener or plaintext mode.
import { createInterface } from 'node:readline';
import { Identity, extractSessionRecoveryToken, decryptResponseWithToken } from 'ehbp';
const lines = createInterface({ input: process.stdin })[Symbol.asyncIterator]();
const publicKey = process.argv[2];
const bytes = Uint8Array.from(publicKey.match(/../g), value => parseInt(value, 16));
const identity = await Identity.fromPublicKeyBytes(bytes);
const { request, context } = await identity.encryptRequestWithContext(new Request('https://gateway.example/v1/rpc', { method: 'POST', body: 'public interoperability fixture' }));
const token = await extractSessionRecoveryToken(context);
console.log(JSON.stringify({ encapsulated: request.headers.get('ehbp-encapsulated-key'), body: Buffer.from(await request.arrayBuffer()).toString('hex') }));
const { value } = await lines.next();
const sealed = JSON.parse(value);
const response = await decryptResponseWithToken(new Response(Buffer.from(sealed.body, 'hex'), { headers: { 'ehbp-response-nonce': sealed.nonce } }), token);
const text = await response.text();
if (text !== '{"interoperable":true}\n') throw new Error('Interoperability mismatch');
process.exit(0);
