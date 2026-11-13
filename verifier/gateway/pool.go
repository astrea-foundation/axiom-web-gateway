package gateway

// Pool verification shares the official CPU/provenance verifier with the
// gateway, then independently appraises every GPU. Device-evidence hashing by
// itself is not an NVIDIA attestation verdict.
import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"strings"
	"time"

	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

const PoolProtocol = "axiom-pool-e2ee-v1"

type PoolIdentity struct {
	WorkerID         string `json:"worker_id"`
	BootID           string `json:"boot_id"`
	EncryptionKey    string `json:"encryption_key"`
	IdentityKey      string `json:"identity_key"`
	ModelManifest    string `json:"model_manifest"`
	LogicalOrigin    string `json:"logical_origin"`
	EvidenceProfile  string `json:"evidence_profile"`
	DeploymentDigest string `json:"deployment_digest"`
}
type PoolIdentityStatement struct {
	Worker    PoolIdentity `json:"worker"`
	Challenge string       `json:"challenge"`
	IssuedAt  int64        `json:"issued_at"`
	ExpiresAt int64        `json:"expires_at"`
}
type PoolPolicy struct {
	SchemaVersion     int      `json:"schema_version"`
	Sequence          uint64   `json:"sequence"`
	IssuedAt          int64    `json:"issued_at"`
	ExpiresAt         int64    `json:"expires_at"`
	MinimumGeneration uint64   `json:"minimum_generation"`
	ConfigRepository  string   `json:"config_repository"`
	NvidiaAnchors     []string `json:"nvidia_anchor_sha256"`
}
type PoolManifest struct {
	SchemaVersion      int                     `json:"schema_version"`
	Generation         uint64                  `json:"generation"`
	SourceRepository   string                  `json:"source_repository"`
	SourceRevision     string                  `json:"source_revision"`
	BuildRecipeSHA256  string                  `json:"build_recipe_sha256"`
	CargoLockSHA256    string                  `json:"cargo_lock_sha256"`
	VerifierLockSHA256 string                  `json:"verifier_lock_sha256"`
	WorkerImageDigest  string                  `json:"worker_image_digest"`
	ConfigRepository   string                  `json:"config_repository"`
	ConfigDigest       string                  `json:"config_digest"`
	CodeMeasurement    measurement.Measurement `json:"code_measurement"`
	ModelManifest      string                  `json:"model_manifest"`
	GPUCount           int                     `json:"gpu_count"`
}
type PoolEvidence struct {
	Protocol  string          `json:"protocol"`
	Challenge string          `json:"challenge"`
	Identity  SignedDocument  `json:"identity"`
	Document  json.RawMessage `json:"document"`
	Manifest  SignedDocument  `json:"manifest"`
	Policy    SignedDocument  `json:"policy"`
}
type NvidiaVerdict struct {
	DeviceID string            `json:"device_id"`
	JWT      string            `json:"jwt"`
	JWKS     json.RawMessage   `json:"jwks"`
	Detached map[string]string `json:"detached"`
}
type PoolContext struct {
	Challenge             string `json:"challenge"`
	Origin                string `json:"origin"`
	PublisherKey          string `json:"publisher_key"`
	ModelManifest         string `json:"model_manifest"`
	Now                   int64  `json:"now"`
	MinimumPolicySequence uint64 `json:"minimum_policy_sequence"`
}
type PoolInput struct {
	Evidence PoolEvidence    `json:"evidence"`
	Context  PoolContext     `json:"context"`
	Nvidia   []NvidiaVerdict `json:"nvidia"`
}
type PoolVerified struct {
	Worker         PoolIdentity `json:"worker"`
	ExpiresAt      int64        `json:"expires_at"`
	PolicySequence uint64       `json:"policy_sequence"`
	Generation     uint64       `json:"generation"`
}

// VerifyWorker is used by the native executable and the browser WASM. All
// NVIDIA network calls happen outside this offline verifier at fixed vendor
// endpoints. Their results remain untrusted until the signatures below pass.
func VerifyWorker(raw []byte) ([]byte, error) { return verifyWorker(raw, productionVerifier) }

func verifyWorker(raw []byte, hardware func([]byte, []byte, string) (*verify.Verification, error)) (output []byte, err error) {
	defer func() {
		if recover() != nil {
			output = nil
			err = rejected
		}
		if err != nil {
			output = nil
			err = rejected
		}
	}()
	if len(raw) > MaxInput {
		return nil, rejected
	}
	var in PoolInput
	if decodeStrict(raw, &in) != nil {
		return nil, rejected
	}
	c, e := in.Context, in.Evidence
	current := time.Now().Unix()
	if !hex32.MatchString(c.Challenge) || e.Challenge != c.Challenge || e.Protocol != PoolProtocol || !httpsOrigin(c.Origin) || !hex32.MatchString(c.PublisherKey) || !hex32.MatchString(c.ModelManifest) || c.Now < current-60 || c.Now > current+60 {
		return nil, rejected
	}
	key, _ := hex.DecodeString(c.PublisherKey)
	var p PoolPolicy
	if signedPool(e.Policy, key, "axiom-pool-policy-v1", &p) != nil {
		return nil, rejected
	}
	repo, tag, pin, parseErr := verify.ParseReference(p.ConfigRepository)
	if parseErr != nil || repo != p.ConfigRepository || tag != "" || pin != "" || p.SchemaVersion != 1 || p.Sequence == 0 || p.Sequence > 9007199254740991 || p.Sequence < c.MinimumPolicySequence || p.MinimumGeneration == 0 || p.MinimumGeneration > 9007199254740991 || p.IssuedAt < 0 || p.IssuedAt > c.Now || p.ExpiresAt <= c.Now || p.ExpiresAt-p.IssuedAt > 86400 || len(p.NvidiaAnchors) == 0 || len(p.NvidiaAnchors) > 8 {
		return nil, rejected
	}
	for _, anchor := range p.NvidiaAnchors {
		if !hex32.MatchString(anchor) {
			return nil, rejected
		}
	}
	var m PoolManifest
	if signedPool(e.Manifest, key, "axiom-pool-workload-v1", &m) != nil {
		return nil, rejected
	}
	if m.SchemaVersion != 1 || m.Generation > 9007199254740991 || m.Generation < p.MinimumGeneration || m.ConfigRepository != p.ConfigRepository || m.SourceRepository != "https://github.com/astrea-foundation/axiom-inference" || !revision.MatchString(m.SourceRevision) || !hex32.MatchString(m.ConfigDigest) || !digest.MatchString(m.WorkerImageDigest) || !hex32.MatchString(m.BuildRecipeSHA256) || !hex32.MatchString(m.CargoLockSHA256) || !hex32.MatchString(m.VerifierLockSHA256) || m.ModelManifest != c.ModelManifest || m.GPUCount != 1 {
		return nil, rejected
	}
	nonce, _ := hex.DecodeString(c.Challenge)
	facts, err := hardware(e.Document, nonce, p.ConfigRepository)
	if err != nil {
		return nil, err
	}
	expected, _ := json.Marshal(m.CodeMeasurement)
	actual, _ := json.Marshal(facts.CodeMeasurement)
	if facts.ConfigRepo != p.ConfigRepository || facts.CodeDigest != m.ConfigDigest || facts.CodeMeasurement == nil || !bytes.Equal(expected, actual) || facts.EnclaveMeasurement == nil || facts.FreshnessExpiresAt.Unix() <= c.Now {
		return nil, rejected
	}
	encHex, err := poolKey(facts, "axiom-pool-encryption", true)
	if err != nil {
		return nil, err
	}
	idHex, err := poolKey(facts, "axiom-pool-identity", false)
	if err != nil {
		return nil, err
	}
	idKey, _ := hex.DecodeString(idHex)
	var statement PoolIdentityStatement
	if signedPool(e.Identity, idKey, "axiom-pool-identity-v1", &statement) != nil {
		return nil, rejected
	}
	w := statement.Worker
	if w.LogicalOrigin != c.Origin || w.ModelManifest != m.ModelManifest || w.DeploymentDigest != m.ConfigDigest || w.EvidenceProfile != "tinfoil-gpu-v3" || w.EncryptionKey != encHex || w.IdentityKey != idHex || !hex32.MatchString(w.BootID) || len(w.WorkerID) != 32 || !lowerHex(w.WorkerID) || statement.Challenge != c.Challenge || statement.IssuedAt > c.Now+30 || statement.ExpiresAt <= c.Now || statement.ExpiresAt-statement.IssuedAt > 240 {
		return nil, rejected
	}
	parsed, err := document.Parse(e.Document, nonce)
	if err != nil {
		return nil, err
	}
	devices := parsed.DeviceEvidenceItems()
	if len(devices) != m.GPUCount || len(in.Nvidia) != m.GPUCount {
		return nil, rejected
	}
	for _, device := range devices {
		if device.Kind != "gpu" || device.Vendor != "nvidia" || device.Format != document.NvidiaGPUEvidenceV1Format {
			return nil, rejected
		}
		var payload map[string]json.RawMessage
		if decodeStrict(device.Evidence, &payload) != nil {
			return nil, rejected
		}
		var gpuNonce string
		if json.Unmarshal(payload["nonce"], &gpuNonce) != nil || gpuNonce != c.Challenge {
			return nil, rejected
		}
		count := 0
		for _, verdict := range in.Nvidia {
			if verdict.DeviceID == device.ID {
				count++
				if verifyNvidia(verdict, p.NvidiaAnchors, c.Challenge, c.Now) != nil {
					return nil, rejected
				}
			}
		}
		if count != 1 {
			return nil, rejected
		}
	}
	expires := min(c.Now+240, p.ExpiresAt, statement.ExpiresAt, facts.FreshnessExpiresAt.Unix())
	return json.Marshal(PoolVerified{w, expires, p.Sequence, m.Generation})
}
func lowerHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func poolKey(facts *verify.Verification, id string, encryption bool) (string, error) {
	value, err := facts.CryptoMaterialData(id, "https://tinfoil.sh/key/spki/v1")
	if err != nil {
		return "", err
	}
	der, err := hex.DecodeString(value)
	if err != nil {
		return "", err
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return "", err
	}
	if encryption {
		k, ok := key.(*ecdh.PublicKey)
		if !ok || k.Curve() != ecdh.X25519() {
			return "", rejected
		}
		return hex.EncodeToString(k.Bytes()), nil
	}
	k, ok := key.(ed25519.PublicKey)
	if !ok {
		return "", rejected
	}
	return hex.EncodeToString(k), nil
}
func signedPool(doc SignedDocument, key []byte, domain string, out any) error {
	if len(doc.Payload) > 180*1024 {
		return rejected
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(doc.Payload)
	if err != nil {
		return rejected
	}
	sig, err := hex.DecodeString(doc.Signature)
	if err != nil || len(key) != 32 || len(sig) != 64 || !ed25519.Verify(key, append([]byte(domain+"\x00"), raw...), sig) {
		return rejected
	}
	return decodeStrict(raw, out)
}
func verifyNvidia(verdict NvidiaVerdict, anchors []string, nonce string, now int64) error {
	overall, err := verifyNvidiaJWT(verdict, anchors, nonce, now)
	if err != nil {
		return err
	}
	truth := func(claims map[string]json.RawMessage, name string) bool {
		var v bool
		return json.Unmarshal(claims[name], &v) == nil && v
	}
	value := func(claims map[string]json.RawMessage, name string) string {
		var v string
		_ = json.Unmarshal(claims[name], &v)
		return v
	}
	if !truth(overall, "x-nvidia-overall-att-result") || value(overall, "x-nvidia-ver") != "3.0" {
		return rejected
	}
	var issued, expires int64
	if json.Unmarshal(overall["iat"], &issued) != nil || json.Unmarshal(overall["exp"], &expires) != nil || issued < now-120 || issued > now+30 || expires <= now || expires <= issued {
		return rejected
	}
	var submods map[string]json.RawMessage
	if decodeStrict(overall["submods"], &submods) != nil || len(submods) != 1 || len(verdict.Detached) != 1 {
		return rejected
	}
	for label, raw := range submods {
		token, ok := verdict.Detached[label]
		if !ok || len(token) > 2*1024*1024 {
			return rejected
		}
		var selector []json.RawMessage
		var kind string
		var digest []string
		if json.Unmarshal(raw, &selector) != nil || len(selector) != 2 || json.Unmarshal(selector[0], &kind) != nil || kind != "DIGEST" || json.Unmarshal(selector[1], &digest) != nil || len(digest) != 2 || digest[0] != "SHA-256" {
			return rejected
		}
		sum := sha256.Sum256([]byte(token))
		if digest[1] != hex.EncodeToString(sum[:]) {
			return rejected
		}
		detached := verdict
		detached.JWT = token
		claims, err := verifyNvidiaJWT(detached, anchors, nonce, now)
		if err != nil {
			return err
		}
		if !truth(claims, "secboot") || value(claims, "dbgstat") != "disabled" || value(claims, "measres") != "success" {
			return rejected
		}
		for _, name := range []string{"x-nvidia-gpu-attestation-report-parsed", "x-nvidia-gpu-attestation-report-signature-verified", "x-nvidia-gpu-attestation-report-nonce-match", "x-nvidia-gpu-attestation-report-cert-chain-fwid-match", "x-nvidia-gpu-driver-rim-signature-verified", "x-nvidia-gpu-vbios-rim-signature-verified"} {
			if !truth(claims, name) {
				return rejected
			}
		}
		for _, name := range []string{"x-nvidia-error-details", "x-nvidia-attestation-warning"} {
			if raw, ok := claims[name]; ok {
				v := string(bytes.TrimSpace(raw))
				if v != "null" && v != "false" && v != `""` && v != "[]" && v != "{}" {
					return rejected
				}
			}
		}
		for _, name := range []string{"x-nvidia-gpu-attestation-report-cert-chain", "x-nvidia-gpu-driver-rim-cert-chain", "x-nvidia-gpu-vbios-rim-cert-chain"} {
			var chain map[string]json.RawMessage
			if decodeStrict(claims[name], &chain) != nil || value(chain, "x-nvidia-cert-status") != "valid" || value(chain, "x-nvidia-cert-ocsp-status") != "good" || !truth(chain, "x-nvidia-cert-ocsp-nonce-matches") || !truth(chain, "x-nvidia-cert-ocsp-response-valid") {
				return rejected
			}
		}
	}
	return nil
}
func verifyNvidiaJWT(verdict NvidiaVerdict, anchors []string, nonce string, now int64) (map[string]json.RawMessage, error) {
	if len(verdict.JWT) > 2*1024*1024 || len(verdict.JWKS) > 2*1024*1024 {
		return nil, rejected
	}
	parts := strings.Split(verdict.JWT, ".")
	if len(parts) != 3 {
		return nil, rejected
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ,omitempty"`
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil || decodeStrict(decoded, &header) != nil || header.Alg != "ES384" || header.Kid == "" {
		return nil, rejected
	}
	var jwks struct {
		Keys []struct {
			Kid string   `json:"kid"`
			X5c []string `json:"x5c"`
		}
	}
	// JWKs contain extra public metadata. Reject duplicate keys but accept
	// vendor-defined public fields; never honor a JWK-supplied URL or root.
	if rejectDuplicateKeys(verdict.JWKS) != nil || json.Unmarshal(verdict.JWKS, &jwks) != nil {
		return nil, rejected
	}
	var chain []string
	matches := 0
	for _, key := range jwks.Keys {
		if key.Kid == header.Kid {
			chain = key.X5c
			matches++
		}
	}
	if matches != 1 || len(chain) < 2 || len(chain) > 4 {
		return nil, rejected
	}
	leafDER, err := base64.StdEncoding.Strict().DecodeString(chain[0])
	if err != nil || len(leafDER) > 64*1024 {
		return nil, rejected
	}
	anchorDER, err := base64.StdEncoding.Strict().DecodeString(chain[1])
	if err != nil || len(anchorDER) > 64*1024 {
		return nil, rejected
	}
	hash := sha256.Sum256(anchorDER)
	approved := false
	for _, a := range anchors {
		if a == hex.EncodeToString(hash[:]) {
			approved = true
		}
	}
	if !approved {
		return nil, rejected
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, rejected
	}
	anchor, err := x509.ParseCertificate(anchorDER)
	if err != nil {
		return nil, rejected
	}
	instant := time.Unix(now, 0)
	if instant.Before(leaf.NotBefore) || instant.After(leaf.NotAfter) || instant.Before(anchor.NotBefore) || instant.After(anchor.NotAfter) || leaf.CheckSignatureFrom(anchor) != nil {
		return nil, rejected
	}
	key, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve.Params().BitSize != 384 {
		return nil, rejected
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(signature) != 96 {
		return nil, rejected
	}
	h := sha512.Sum384([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(key, h[:], new(big.Int).SetBytes(signature[:48]), new(big.Int).SetBytes(signature[48:])) {
		return nil, rejected
	}
	var payload map[string]json.RawMessage
	decoded, err = base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || decodeStrict(decoded, &payload) != nil {
		return nil, rejected
	}
	var gotNonce string
	if json.Unmarshal(payload["eat_nonce"], &gotNonce) != nil || gotNonce != nonce {
		return nil, rejected
	}
	var issuer string
	if json.Unmarshal(payload["iss"], &issuer) != nil || issuer != "https://nras.attestation.nvidia.com" {
		return nil, rejected
	}
	if raw, ok := payload["exp"]; ok {
		var exp int64
		if json.Unmarshal(raw, &exp) != nil || exp <= now {
			return nil, rejected
		}
	}
	if raw, ok := payload["iat"]; ok {
		var iat int64
		if json.Unmarshal(raw, &iat) != nil || iat > now+30 {
			return nil, rejected
		}
	}
	if raw, ok := payload["nbf"]; ok {
		var nbf int64
		if json.Unmarshal(raw, &nbf) != nil || nbf > now+30 {
			return nil, rejected
		}
	}
	return payload, nil
}
func decodeStrict(raw []byte, out any) error {
	if rejectDuplicateKeys(raw) != nil {
		return rejected
	}
	return decode(raw, out)
}
func rejectDuplicateKeys(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var consume func(int) error
	consume = func(depth int) error {
		if depth > 64 {
			return rejected
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				s, ok := key.(string)
				if err != nil || !ok || seen[s] {
					return rejected
				}
				seen[s] = true
				if consume(depth+1) != nil {
					return rejected
				}
			}
		case '[':
			for d.More() {
				if consume(depth+1) != nil {
					return rejected
				}
			}
		default:
			return rejected
		}
		_, err = d.Token()
		return err
	}
	if consume(0) != nil {
		return rejected
	}
	if _, err := d.Token(); err != io.EOF {
		return rejected
	}
	return nil
}
