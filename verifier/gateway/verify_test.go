package gateway

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	sevabi "github.com/tinfoilsh/go-sev-guest/abi"
	sevp "github.com/tinfoilsh/go-sev-guest/proto/sevsnp"
	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) (Input, ed25519.PrivateKey, *verify.Verification) {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	authPub, _, _ := ed25519.GenerateKey(rand.Reader)
	encKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	authDER, _ := x509.MarshalPKIXPublicKey(authPub)
	encDER, _ := x509.MarshalPKIXPublicKey(encKey.PublicKey())
	c := Context{strings.Repeat("01", 32), "https://gateway.example", hex.EncodeToString(pub), time.Now().Unix(), 4}
	p := Policy{2, 4, c.Now - 10, c.Now + 3600, 2, "astrea-foundation/axiom-web-gateway-config"}
	m := Manifest{SchemaVersion: 2, Generation: 2, SourceRepository: "https://github.com/astrea-foundation/axiom-web-gateway", SourceRevision: strings.Repeat("a", 40), BuildRecipeSHA256: strings.Repeat("b", 64), CargoLockSHA256: strings.Repeat("c", 64), VerifierLockSHA256: strings.Repeat("d", 64), GatewayImageDigest: "sha256:" + strings.Repeat("e", 64), ConfigRepository: p.ConfigRepository, ConfigDigest: strings.Repeat("f", 64), CodeMeasurement: measurement.Measurement{Type: measurement.SnpTdxMultiPlatformV1, Registers: []string{strings.Repeat("1", 96), strings.Repeat("2", 96), strings.Repeat("3", 96)}}, PublicOrigin: c.Origin}
	e := Evidence{Protocol: Protocol, Challenge: c.Challenge, Origin: c.Origin, EncryptionKey: hex.EncodeToString(encKey.PublicKey().Bytes()), AuthorizationKey: hex.EncodeToString(authPub), Document: json.RawMessage(`{"public_fixture":true}`), Policy: signFixture(p, key, "axiom-gateway-policy-v2"), Manifest: signFixture(m, key, "axiom-gateway-workload-v2")}
	f := &verify.Verification{ConfigRepo: p.ConfigRepository, CodeDigest: m.ConfigDigest, CodeMeasurement: &m.CodeMeasurement, EnclaveMeasurement: &measurement.Measurement{Type: measurement.TdxGuestV2}, FreshnessExpiresAt: time.Now().Add(time.Hour), CryptoMaterial: []document.CryptoMaterialItem{{ID: "axiom-encryption", Format: "https://tinfoil.sh/key/spki/v1", Data: hex.EncodeToString(encDER)}, {ID: "axiom-authorization", Format: "https://tinfoil.sh/key/spki/v1", Data: hex.EncodeToString(authDER)}}}
	return Input{e, c}, key, f
}
func signFixture(value any, key ed25519.PrivateKey, domain string) SignedDocument {
	raw, _ := json.Marshal(value)
	return SignedDocument{base64.RawURLEncoding.EncodeToString(raw), hex.EncodeToString(ed25519.Sign(key, append([]byte(domain+"\x00"), raw...)))}
}
func TestPolicyKeyAndMeasurementBindings(t *testing.T) {
	cases := map[string]func(*Input, *verify.Verification){
		"valid":           func(*Input, *verify.Verification) {},
		"wrong-nonce":     func(i *Input, _ *verify.Verification) { i.Context.Challenge = strings.Repeat("02", 32) },
		"wrong-origin":    func(i *Input, _ *verify.Verification) { i.Context.Origin = "https://attacker.example" },
		"wrong-key":       func(i *Input, _ *verify.Verification) { i.Evidence.EncryptionKey = strings.Repeat("03", 32) },
		"wrong-auth":      func(i *Input, _ *verify.Verification) { i.Evidence.AuthorizationKey = strings.Repeat("03", 32) },
		"wrong-publisher": func(i *Input, _ *verify.Verification) { i.Context.PublisherKey = strings.Repeat("03", 32) },
		"rollback":        func(i *Input, _ *verify.Verification) { i.Context.MinimumPolicySequence = 5 },
		"legacy":          func(i *Input, _ *verify.Verification) { i.Evidence.Protocol = "axiom-gateway-v1" },
		"wrong-build":     func(_ *Input, f *verify.Verification) { f.CodeDigest = strings.Repeat("04", 32) },
		"wrong-measurement": func(_ *Input, f *verify.Verification) {
			m := *f.CodeMeasurement
			m.Registers = []string{"wrong"}
			f.CodeMeasurement = &m
		},
		"unsupported-cpu":  func(_ *Input, f *verify.Verification) { f.EnclaveMeasurement.Type = "unsupported" },
		"expired-evidence": func(_ *Input, f *verify.Verification) { f.FreshnessExpiresAt = time.Now().Add(-time.Minute) },
		"missing-key":      func(_ *Input, f *verify.Verification) { f.CryptoMaterial = f.CryptoMaterial[:1] },
	}
	for _, platform := range []string{measurement.TdxGuestV2, measurement.SevGuestV2} {
		for name, change := range cases {
			t.Run(platform+"/"+name, func(t *testing.T) {
				in, _, facts := fixture(t)
				facts.EnclaveMeasurement.Type = platform
				change(&in, facts)
				raw, _ := json.Marshal(in)
				out, err := verifyInput(raw, func(doc, nonce []byte, repo string) (*verify.Verification, error) {
					if len(nonce) != 32 || repo != facts.ConfigRepo {
						t.Fatal("untrusted hardware expectations")
					}
					return facts, nil
				})
				if name == "valid" {
					if err != nil {
						t.Fatal(err)
					}
					var v Verified
					json.Unmarshal(out, &v)
					if v.EvidenceExpiresAt != in.Context.Now+240 || v.EncryptionKey != in.Evidence.EncryptionKey {
						t.Fatal("wrong verified projection")
					}
				} else if err == nil || string(out) != "" || err.Error() != "gateway attestation failed" {
					t.Fatal("unsafe acceptance or error disclosure")
				}
			})
		}
	}
}

func TestStrictSNPRejectsDebugMigrationAndProvisionalFirmware(t *testing.T) {
	cases := map[string]func(*sevp.Report){
		"valid":             func(*sevp.Report) {},
		"debug":             func(r *sevp.Report) { r.Policy = sevabi.SnpPolicyToBytes(sevabi.SnpPolicy{Debug: true}) },
		"migration":         func(r *sevp.Report) { r.Policy = sevabi.SnpPolicyToBytes(sevabi.SnpPolicy{MigrateMA: true}) },
		"vmpl":              func(r *sevp.Report) { r.Vmpl = 1 },
		"provisional-tcb":   func(r *sevp.Report) { r.CurrentTcb = 1 },
		"provisional-build": func(r *sevp.Report) { r.CurrentBuild = 1 },
		"provisional-major": func(r *sevp.Report) { r.CurrentMajor = 1 },
		"provisional-minor": func(r *sevp.Report) { r.CurrentMinor = 1 },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			r := &sevp.Report{Policy: sevabi.SnpPolicyToBytes(sevabi.SnpPolicy{})}
			change(r)
			if (strictSNP(r) == nil) != (name == "valid") {
				t.Fatal("incorrect SNP production policy")
			}
		})
	}
	if strictSNP(nil) == nil {
		t.Fatal("missing SNP report accepted")
	}
}
func TestProductionRejectsFabricatedHardware(t *testing.T) {
	in, _, _ := fixture(t)
	raw, _ := json.Marshal(in)
	if out, err := Verify(raw); err == nil || len(out) != 0 {
		t.Fatal("fabricated quote accepted")
	}
}
func TestSignedDocumentsRejectTamperAndDomainConfusion(t *testing.T) {
	_, key, _ := fixture(t)
	doc := signFixture(map[string]any{"ok": true}, key, "policy")
	var out map[string]any
	if signed(doc, key.Public().(ed25519.PublicKey), "policy", &out) != nil {
		t.Fatal("valid signature rejected")
	}
	for _, domain := range []string{"workload", ""} {
		if signed(doc, key.Public().(ed25519.PublicKey), domain, &out) == nil {
			t.Fatal("domain confusion")
		}
	}
	doc.Payload = base64.RawURLEncoding.EncodeToString([]byte(`{"ok":false}`))
	if signed(doc, key.Public().(ed25519.PublicKey), "policy", &out) == nil {
		t.Fatal("tamper accepted")
	}
}
