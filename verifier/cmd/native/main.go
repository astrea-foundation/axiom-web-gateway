package main

import (
	"fmt"
	"github.com/astrea-foundation/axiom-web-gateway/verifier/gateway"
	"io"
	"os"
)

func main() {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, gateway.MaxInput+1))
	if err == nil {
		var out []byte
		out, err = gateway.Verify(raw)
		if err == nil {
			fmt.Println(string(out))
			return
		}
	}
	fmt.Fprintln(os.Stderr, "gateway attestation failed")
	os.Exit(1)
}
