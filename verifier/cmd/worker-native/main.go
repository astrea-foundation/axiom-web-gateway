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
		if out, err := gateway.VerifyWorker(raw); err == nil {
			fmt.Println(string(out))
			return
		}
	}
	fmt.Fprintln(os.Stderr, "worker attestation failed")
	os.Exit(1)
}
