//go:build js && wasm

package main

import (
	"github.com/astrea-foundation/axiom-web-gateway/verifier/gateway"
	"syscall/js"
)

func main() {
	fn := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) != 1 || args[0].Type() != js.TypeString {
			return map[string]any{"error": "gateway attestation failed"}
		}
		raw := args[0].String()
		if len(raw) > gateway.MaxInput {
			return map[string]any{"error": "gateway attestation failed"}
		}
		out, err := gateway.Verify([]byte(raw))
		if err != nil {
			return map[string]any{"error": "gateway attestation failed"}
		}
		return map[string]any{"result": string(out)}
	})
	js.Global().Set("axiomVerifyGatewayV2", fn)
	select {}
}
