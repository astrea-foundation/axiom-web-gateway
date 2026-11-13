package gateway

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"math/big"
	"strings"
	"testing"
	"time"
)

// Synthetic keys and certificates exercise cryptographic checks, never vendor
// trust. The test anchor is supplied directly to the private appraisal helper.
func gpuFixture(t *testing.T) (func(map[string]any, ...map[string]any) NvidiaVerdict, []string, int64) {
	t.Helper()
	now := time.Now().Unix()
	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-test-only"}, NotBefore: time.Unix(now-60, 0), NotAfter: time.Unix(now+600, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Unix(now-60, 0), NotAfter: time.Unix(now+300, 0), KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	jwks, _ := json.Marshal(map[string]any{"keys": []any{map[string]any{"kid": "fixture", "kty": "EC", "x5c": []string{base64.StdEncoding.EncodeToString(leafDER), base64.StdEncoding.EncodeToString(caDER)}}}})
	anchor := sha256.Sum256(caDER)
	jwt := func(claims map[string]any) string {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES384","kid":"fixture"}`))
		raw, _ := json.Marshal(claims)
		body := header + "." + base64.RawURLEncoding.EncodeToString(raw)
		digest := sha512.Sum384([]byte(body))
		r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		sig := make([]byte, 96)
		r.FillBytes(sig[:48])
		s.FillBytes(sig[48:])
		return body + "." + base64.RawURLEncoding.EncodeToString(sig)
	}
	sign := func(claims map[string]any, overrides ...map[string]any) NvidiaVerdict {
		device := map[string]any{"iss": "https://nras.attestation.nvidia.com", "eat_nonce": claims["eat_nonce"], "secboot": true, "dbgstat": "disabled", "measres": "success"}
		for _, name := range []string{"x-nvidia-gpu-attestation-report-parsed", "x-nvidia-gpu-attestation-report-signature-verified", "x-nvidia-gpu-attestation-report-nonce-match", "x-nvidia-gpu-attestation-report-cert-chain-fwid-match", "x-nvidia-gpu-driver-rim-signature-verified", "x-nvidia-gpu-vbios-rim-signature-verified"} {
			device[name] = true
		}
		for _, name := range []string{"x-nvidia-gpu-attestation-report-cert-chain", "x-nvidia-gpu-driver-rim-cert-chain", "x-nvidia-gpu-vbios-rim-cert-chain"} {
			device[name] = map[string]any{"x-nvidia-cert-status": "valid", "x-nvidia-cert-ocsp-status": "good", "x-nvidia-cert-ocsp-nonce-matches": true, "x-nvidia-cert-ocsp-response-valid": true}
		}
		for _, override := range overrides {
			for k, v := range override {
				device[k] = v
			}
		}
		token := jwt(device)
		digest := sha256.Sum256([]byte(token))
		overall := map[string]any{}
		for k, v := range claims {
			overall[k] = v
		}
		overall["iss"] = "https://nras.attestation.nvidia.com"
		overall["x-nvidia-ver"] = "3.0"
		overall["submods"] = map[string]any{"GPU-0": []any{"DIGEST", []string{"SHA-256", hex.EncodeToString(digest[:])}}}
		return NvidiaVerdict{DeviceID: "gpu-0", JWT: jwt(overall), JWKS: jwks, Detached: map[string]string{"GPU-0": token}}
	}
	return sign, []string{hex.EncodeToString(anchor[:])}, now
}

func TestNvidiaVerdictBindsNonceResultCertificateAndSignature(t *testing.T) {
	sign, anchors, now := gpuFixture(t)
	nonce := strings.Repeat("ab", 32)
	claims := func() map[string]any {
		return map[string]any{"eat_nonce": nonce, "x-nvidia-overall-att-result": true, "iat": now, "exp": now + 120}
	}
	valid := sign(claims())
	if err := verifyNvidia(valid, anchors, nonce, now); err != nil {
		t.Fatalf("valid synthetic verdict rejected: %v", err)
	}
	for _, change := range []string{"nonce", "result", "expiry", "future"} {
		c := claims()
		switch change {
		case "nonce":
			c["eat_nonce"] = strings.Repeat("cd", 32)
		case "result":
			c["x-nvidia-overall-att-result"] = false
		case "expiry":
			c["exp"] = now
		case "future":
			c["iat"] = now + 31
		}
		if verifyNvidia(sign(c), anchors, nonce, now) == nil {
			t.Fatalf("accepted %s", change)
		}
	}
	if verifyNvidia(valid, []string{strings.Repeat("00", 32)}, nonce, now) == nil {
		t.Fatal("accepted untrusted certificate")
	}
	if verifyNvidia(valid, anchors, nonce, now+601) == nil {
		t.Fatal("accepted expired certificate")
	}
	bad := valid
	parts := strings.Split(valid.JWT, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sig[0] ^= 1
	parts[2] = base64.RawURLEncoding.EncodeToString(sig)
	bad.JWT = strings.Join(parts, ".")
	if verifyNvidia(bad, anchors, nonce, now) == nil {
		t.Fatal("accepted invalid signature")
	}
	bad = valid
	bad.JWKS = []byte(`{"keys":[],"keys":[]}`)
	if verifyNvidia(bad, anchors, nonce, now) == nil {
		t.Fatal("accepted ambiguous JWKS")
	}
}

func TestPoolRejectsFixturesAndAmbiguousJSON(t *testing.T) {
	for _, raw := range []string{`{"evidence":{"document":{"test_fixture_only":true}}}`, `{"context":{},"context":{}}`, `{"a":{"b":1,"b":2}}`} {
		if _, err := VerifyWorker([]byte(raw)); err == nil {
			t.Fatal("accepted unverified evidence")
		}
	}
	if rejectDuplicateKeys([]byte(`{"outer":{"key":1,"\u006bey":2}}`)) == nil {
		t.Fatal("accepted escaped duplicate")
	}
}

func TestNvidiaDetachedClaimsRequireSecureBootNoDebugMeasurementsAndRevocation(t *testing.T) {
	sign, anchors, now := gpuFixture(t)
	nonce := strings.Repeat("ab", 32)
	overall := map[string]any{"eat_nonce": nonce, "x-nvidia-overall-att-result": true, "iat": now, "exp": now + 120}
	cases := map[string]map[string]any{
		"debug-enabled": {"dbgstat": "enabled"}, "secure-boot-disabled": {"secboot": false},
		"measurement-failure": {"measres": "fail"}, "wrong-device-nonce": {"eat_nonce": strings.Repeat("cd", 32)},
		"bad-report-signature":     {"x-nvidia-gpu-attestation-report-signature-verified": false},
		"certificate-revoked":      {"x-nvidia-gpu-attestation-report-cert-chain": map[string]any{"x-nvidia-cert-status": "revoked", "x-nvidia-cert-ocsp-status": "revoked", "x-nvidia-cert-ocsp-nonce-matches": true, "x-nvidia-cert-ocsp-response-valid": true}},
		"certificate-hold-warning": {"x-nvidia-attestation-warning": true},
		"vendor-error":             {"x-nvidia-error-details": map[string]any{"error": "synthetic"}},
	}
	for name, changes := range cases {
		t.Run(name, func(t *testing.T) {
			if verifyNvidia(sign(overall, changes), anchors, nonce, now) == nil {
				t.Fatal("accepted an overall pass with unsafe device claims")
			}
		})
	}
	for _, change := range []string{"missing-detached", "changed-digest", "wrong-label"} {
		v := sign(overall)
		switch change {
		case "missing-detached":
			v.Detached = nil
		case "changed-digest":
			v.Detached["GPU-0"] += "x"
		case "wrong-label":
			v.Detached = map[string]string{"GPU-1": v.Detached["GPU-0"]}
		}
		if verifyNvidia(v, anchors, nonce, now) == nil {
			t.Fatal("accepted", change)
		}
	}
}

func TestCompletePoolPolicyCPUKeyModelAndGPUComposition(t *testing.T) {
	for _, change := range []string{"valid", "model", "origin", "policy-rollback", "endorsement", "gpu-result", "generation-overflow"} {
		t.Run(change, func(t *testing.T) {
			gateway, publisher, facts := fixture(t)
			var gm Manifest
			raw, _ := base64.RawURLEncoding.DecodeString(gateway.Evidence.Manifest.Payload)
			if json.Unmarshal(raw, &gm) != nil {
				t.Fatal("fixture")
			}
			idPublic, idPrivate, _ := ed25519.GenerateKey(rand.Reader)
			der, _ := x509.MarshalPKIXPublicKey(idPublic)
			facts.CryptoMaterial[0].ID = "axiom-pool-encryption"
			facts.CryptoMaterial[1] = document.CryptoMaterialItem{ID: "axiom-pool-identity", Format: "https://tinfoil.sh/key/spki/v1", Data: hex.EncodeToString(der)}
			gpuSign, anchors, now := gpuFixture(t)
			nonce := gateway.Context.Challenge
			policy := PoolPolicy{SchemaVersion: 1, Sequence: 4, IssuedAt: now - 10, ExpiresAt: now + 3600, MinimumGeneration: 2, ConfigRepository: facts.ConfigRepo, NvidiaAnchors: anchors}
			manifest := PoolManifest{SchemaVersion: 1, Generation: 2, SourceRepository: "https://github.com/astrea-foundation/axiom-inference", SourceRevision: gm.SourceRevision, BuildRecipeSHA256: gm.BuildRecipeSHA256, CargoLockSHA256: gm.CargoLockSHA256, VerifierLockSHA256: gm.VerifierLockSHA256, WorkerImageDigest: gm.GatewayImageDigest, ConfigRepository: facts.ConfigRepo, ConfigDigest: facts.CodeDigest, CodeMeasurement: *facts.CodeMeasurement, ModelManifest: strings.Repeat("aa", 32), GPUCount: 1}
			worker := PoolIdentity{WorkerID: strings.Repeat("11", 16), BootID: strings.Repeat("22", 32), EncryptionKey: gateway.Evidence.EncryptionKey, IdentityKey: hex.EncodeToString(idPublic), ModelManifest: manifest.ModelManifest, LogicalOrigin: "https://worker.example", EvidenceProfile: "tinfoil-gpu-v3", DeploymentDigest: facts.CodeDigest}
			cpuNonce, _ := hex.DecodeString(nonce)
			gpuEvidence, _ := json.Marshal(map[string]any{"nonce": nonce})
			doc, err := document.Build(document.BuildInput{Nonce: cpuNonce, CryptoMaterial: facts.CryptoMaterial, DeviceEvidence: []document.DeviceEvidenceItem{{ID: "gpu-0", Kind: "gpu", Vendor: "nvidia", Format: document.NvidiaGPUEvidenceV1Format, Evidence: jsontext.Value(gpuEvidence)}}}, func([64]byte) (string, []byte, error) {
				return document.TDXQuoteV1Format, []byte("synthetic-no-hardware"), nil
			})
			if err != nil {
				t.Fatal(err)
			}
			claims := map[string]any{"eat_nonce": nonce, "x-nvidia-overall-att-result": true, "exp": now + 120, "iat": now}
			context := PoolContext{Challenge: nonce, Origin: worker.LogicalOrigin, PublisherKey: gateway.Context.PublisherKey, ModelManifest: manifest.ModelManifest, Now: now, MinimumPolicySequence: 4}
			switch change {
			case "model":
				context.ModelManifest = strings.Repeat("bb", 32)
			case "origin":
				context.Origin = "https://attacker.example"
			case "policy-rollback":
				context.MinimumPolicySequence = 5
			case "endorsement":
				facts.CryptoMaterial = facts.CryptoMaterial[:1]
			case "gpu-result":
				claims["x-nvidia-overall-att-result"] = false
			case "generation-overflow":
				manifest.Generation = 9007199254740992
			}
			evidence := PoolEvidence{Protocol: PoolProtocol, Challenge: nonce, Identity: signFixture(PoolIdentityStatement{worker, nonce, now, now + 240}, idPrivate, "axiom-pool-identity-v1"), Document: doc, Manifest: signFixture(manifest, publisher, "axiom-pool-workload-v1"), Policy: signFixture(policy, publisher, "axiom-pool-policy-v1")}
			input, _ := json.Marshal(PoolInput{evidence, context, []NvidiaVerdict{gpuSign(claims)}})
			out, err := verifyWorker(input, func([]byte, []byte, string) (*verify.Verification, error) { return facts, nil })
			if change == "valid" {
				if err != nil || len(out) == 0 {
					t.Fatal("valid composed synthetic proof rejected", err)
				}
			} else if err == nil || len(out) != 0 {
				t.Fatal("accepted", change)
			}
			if _, err = VerifyWorker(input); err == nil {
				t.Fatal("production accepted fabricated CPU evidence")
			}
		})
	}
}
