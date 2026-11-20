import { initialize, verifyLocally } from './verifier-runtime.js';
const worker = globalThis as unknown as { onmessage: (event: MessageEvent) => void; postMessage(value: unknown): void };
worker.onmessage = async ({ data }) => {
  try {
    if (data.input === undefined) {
      await initialize(data.bytes);
      worker.postMessage({ id: data.id, result: '' });
    } else {
      worker.postMessage({ id: data.id, result: await verifyLocally(data.input, data.bytes) });
    }
  }
  catch { worker.postMessage({ id: data.id, error: 'gateway attestation failed' }); }
};
