// Packaged Go runtime and pinned Tinfoil verification code; no remote executable imports.
import '../wasm/wasm_exec.js';

declare global {
  var Go: new () => { importObject: WebAssembly.Imports; run(instance: WebAssembly.Instance): Promise<void> };
  var axiomVerifyGatewayV2: ((input: string) => { result?: string; error?: string }) | undefined;
}
let ready: Promise<void> | undefined;
export function initialize(bytes?: BufferSource): Promise<void> {
  return ready ??= (async () => {
    const go = new globalThis.Go();
    const source = bytes ?? await (async () => {
      const response = await fetch(new URL('../wasm/axiom_gateway_verifier.wasm', import.meta.url), { credentials: 'omit', redirect: 'error' });
      if (!response.ok) throw new Error('Gateway verifier unavailable');
      return response.arrayBuffer();
    })();
    const { instance } = await WebAssembly.instantiate(source, go.importObject);
    void go.run(instance).catch(() => { globalThis.axiomVerifyGatewayV2 = undefined; });
    if (!globalThis.axiomVerifyGatewayV2) throw new Error('Gateway verifier unavailable');
  })();
}
export async function verifyLocally(input: string, bytes?: BufferSource): Promise<string> {
  await initialize(bytes);
  const output = globalThis.axiomVerifyGatewayV2?.(input);
  if (!output?.result || output.error) throw new Error('gateway attestation failed');
  return output.result;
}
