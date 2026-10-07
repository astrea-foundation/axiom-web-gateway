// Package gateway applies Axiom policy to the official offline Tinfoil verifier.
// Native and browser WASM builds use this same code and embedded trust roots.
package gateway

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	tdxabi "github.com/google/go-tdx-guest/abi"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	sevabi "github.com/tinfoilsh/go-sev-guest/abi"
	sevp "github.com/tinfoilsh/go-sev-guest/proto/sevsnp"
	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
	"io"
	"net/url"
	"regexp"
	"time"
)

const Protocol = "axiom-gateway-v2"
const MaxInput = 8 * 1024 * 1024

var rejected = errors.New("gateway attestation failed")
var hex32 = regexp.MustCompile(`^[0-9a-f]{64}$`)
var digest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var revision = regexp.MustCompile(`^[0-9a-f]{40}$`)

type SignedDocument struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}
type Policy struct {
	SchemaVersion     int    `json:"schema_version"`
	Sequence          uint64 `json:"sequence"`
	IssuedAt          int64  `json:"issued_at"`
	ExpiresAt         int64  `json:"expires_at"`
	MinimumGeneration uint64 `json:"minimum_generation"`
	ConfigRepository  string `json:"config_repository"`
}
type Manifest struct {
	SchemaVersion      int                     `json:"schema_version"`
	Generation         uint64                  `json:"generation"`
	SourceRepository   string                  `json:"source_repository"`
	SourceRevision     string                  `json:"source_revision"`
	BuildRecipeSHA256  string                  `json:"build_recipe_sha256"`
	CargoLockSHA256    string                  `json:"cargo_lock_sha256"`
	VerifierLockSHA256 string                  `json:"verifier_lock_sha256"`
	GatewayImageDigest string                  `json:"gateway_image_digest"`
	ConfigRepository   string                  `json:"config_repository"`
	ConfigDigest       string                  `json:"config_digest"`
	CodeMeasurement    measurement.Measurement `json:"code_measurement"`
	PublicOrigin       string                  `json:"public_origin"`
}
type Evidence struct {
	Protocol         string          `json:"protocol"`
	Challenge        string          `json:"challenge"`
	Origin           string          `json:"origin"`
	EncryptionKey    string          `json:"encryption_key"`
	AuthorizationKey string          `json:"authorization_key"`
	Document         json.RawMessage `json:"document"`
	Manifest         SignedDocument  `json:"manifest"`
	Policy           SignedDocument  `json:"policy"`
}
type Context struct {
	Challenge             string `json:"challenge"`
	Origin                string `json:"origin"`
	PublisherKey          string `json:"publisher_key"`
	Now                   int64  `json:"now"`
	MinimumPolicySequence uint64 `json:"minimum_policy_sequence"`
}
type Input struct {
	Evidence Evidence `json:"evidence"`
	Context  Context  `json:"context"`
}
type Verified struct {
	EncryptionKey     string `json:"encryption_key"`
	AuthorizationKey  string `json:"authorization_key"`
	Origin            string `json:"origin"`
	ImageDigest       string `json:"image_digest"`
	SourceRepository  string `json:"source_repository"`
	SourceRevision    string `json:"source_revision"`
	ConfigRepository  string `json:"config_repository"`
	ConfigDigest      string `json:"config_digest"`
	Generation        uint64 `json:"generation"`
	PolicySequence    uint64 `json:"policy_sequence"`
	PolicyExpiresAt   int64  `json:"policy_expires_at"`
	EvidenceExpiresAt int64  `json:"evidence_expires_at"`
}

func decode(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return rejected
	}
	return nil
}
func signed(doc SignedDocument, key []byte, domain string, out any) error {
	if len(doc.Payload) > 128*1024 {
		return rejected
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(doc.Payload)
	if err != nil {
		return rejected
	}
	sig, err := hex.DecodeString(doc.Signature)
	if err != nil || len(sig) != 64 {
		return rejected
	}
	if !ed25519.Verify(ed25519.PublicKey(key), append([]byte(domain+"\x00"), raw...), sig) {
		return rejected
	}
	return decode(raw, out)
}
func httpsOrigin(s string) bool {
	u, err := url.Parse(s)
	return err == nil && len(s) <= 512 && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && u.Path == "" && s == "https://"+u.Host
}

// Verify does no network I/O and accepts neither custom roots nor freshness bypasses.
func Verify(raw []byte) ([]byte, error) { return verifyInput(raw, productionVerifier) }

func productionVerifier(doc, nonce []byte, repo string) (*verify.Verification, error) {
	v, err := verify.NewVerifier()
	if err != nil {
		return nil, err
	}
	facts, err := v.VerifyV3(doc, nonce, repo)
	if err != nil {
		return nil, err
	}
	// Endorsements authenticate the fleet policy. Axiom additionally rejects
	// debug/migration capabilities and provisional SNP firmware even if a
	// future endorsed development policy were to permit them.
	parsed, err := document.Parse(doc, nonce)
	if err != nil {
		return nil, err
	}
	cpu := parsed.CPUEvidence()
	switch cpu.Format {
	case document.SEVSNPReportV1Format:
		report, err := sevabi.ReportToProto(cpu.Report)
		if err != nil || strictSNP(report) != nil {
			return nil, rejected
		}
	case document.TDXQuoteV1Format:
		quote, err := tdxabi.QuoteToProto(cpu.Report)
		if err != nil {
			return nil, rejected
		}
		q, ok := quote.(*tdxpb.QuoteV4)
		if !ok || len(q.GetTdQuoteBody().GetTdAttributes()) != 8 || binary.LittleEndian.Uint64(q.GetTdQuoteBody().GetTdAttributes())&1 != 0 {
			return nil, rejected
		}
	default:
		return nil, rejected
	}
	return facts, nil
}

func strictSNP(report *sevp.Report) error {
	if report == nil {
		return rejected
	}
	policy, err := sevabi.ParseSnpPolicy(report.GetPolicy())
	if err != nil || policy.Debug || policy.MigrateMA || report.GetVmpl() != 0 ||
		report.GetCurrentTcb() != report.GetCommittedTcb() ||
		report.GetCurrentBuild() != report.GetCommittedBuild() ||
		report.GetCurrentMajor() != report.GetCommittedMajor() ||
		report.GetCurrentMinor() != report.GetCommittedMinor() {
		return rejected
	}
	return nil
}

// The injected function is unexported and used only by unit tests to isolate
// Axiom policy from vendor evidence. Production always calls NewVerifier above.
func verifyInput(raw []byte, hardware func([]byte, []byte, string) (*verify.Verification, error)) (output []byte, err error) {
	defer func() {
		if recover() != nil {
			output = nil
			err = rejected
		}
		if err != nil {
			err = rejected
		}
	}()
	if len(raw) > MaxInput {
		return nil, rejected
	}
	var in Input
	if decode(raw, &in) != nil {
		return nil, rejected
	}
	c, e := in.Context, in.Evidence
	if !hex32.MatchString(c.Challenge) || e.Challenge != c.Challenge || e.Protocol != Protocol || e.Origin != c.Origin || !httpsOrigin(c.Origin) || !hex32.MatchString(c.PublisherKey) {
		return nil, rejected
	}
	current := time.Now().Unix()
	if c.Now < current-60 || c.Now > current+60 {
		return nil, rejected
	}
	key, _ := hex.DecodeString(c.PublisherKey)
	var p Policy
	if signed(e.Policy, key, "axiom-gateway-policy-v2", &p) != nil {
		return nil, rejected
	}
	repo, tag, pin, parseErr := verify.ParseReference(p.ConfigRepository)
	if parseErr != nil || repo != p.ConfigRepository || tag != "" || pin != "" || p.SchemaVersion != 2 || p.Sequence < c.MinimumPolicySequence || p.Sequence == 0 || p.Sequence > 9007199254740991 || p.MinimumGeneration == 0 || p.MinimumGeneration > 9007199254740991 || p.IssuedAt > c.Now || p.ExpiresAt <= c.Now || p.ExpiresAt <= p.IssuedAt || p.ExpiresAt-p.IssuedAt > 86400 {
		return nil, rejected
	}
	var m Manifest
	if signed(e.Manifest, key, "axiom-gateway-workload-v2", &m) != nil {
		return nil, rejected
	}
	if m.SchemaVersion != 2 || m.Generation < p.MinimumGeneration || m.Generation > 9007199254740991 || m.ConfigRepository != p.ConfigRepository || m.PublicOrigin != c.Origin || !digest.MatchString(m.GatewayImageDigest) || !hex32.MatchString(m.ConfigDigest) || !hex32.MatchString(m.BuildRecipeSHA256) || !hex32.MatchString(m.CargoLockSHA256) || !hex32.MatchString(m.VerifierLockSHA256) || !revision.MatchString(m.SourceRevision) || m.SourceRepository != "https://github.com/astrea-foundation/axiom-web-gateway" {
		return nil, rejected
	}
	nonce, _ := hex.DecodeString(c.Challenge)
	facts, err := hardware(e.Document, nonce, p.ConfigRepository)
	if err != nil {
		return nil, err
	}
	expected, _ := json.Marshal(m.CodeMeasurement)
	actual, _ := json.Marshal(facts.CodeMeasurement)
	if facts.ConfigRepo != p.ConfigRepository || facts.EnclaveMeasurement == nil ||
		(facts.EnclaveMeasurement.Type != measurement.TdxGuestV2 && facts.EnclaveMeasurement.Type != measurement.SevGuestV2) ||
		facts.CodeMeasurement == nil || !bytes.Equal(expected, actual) || facts.CodeDigest != m.ConfigDigest || facts.FreshnessExpiresAt.Unix() <= c.Now {
		return nil, rejected
	}
	enc, err := facts.CryptoMaterialData("axiom-encryption", "https://tinfoil.sh/key/spki/v1")
	if err != nil {
		return nil, err
	}
	auth, err := facts.CryptoMaterialData("axiom-authorization", "https://tinfoil.sh/key/spki/v1")
	if err != nil {
		return nil, err
	}
	encDER, err := hex.DecodeString(enc)
	if err != nil {
		return nil, err
	}
	encAny, err := x509.ParsePKIXPublicKey(encDER)
	if err != nil {
		return nil, err
	}
	encKey, ok := encAny.(*ecdh.PublicKey)
	if !ok || encKey.Curve() != ecdh.X25519() {
		return nil, rejected
	}
	authDER, err := hex.DecodeString(auth)
	if err != nil {
		return nil, err
	}
	authAny, err := x509.ParsePKIXPublicKey(authDER)
	if err != nil {
		return nil, err
	}
	authKey, ok := authAny.(ed25519.PublicKey)
	if !ok {
		return nil, rejected
	}
	encHex, authHex := hex.EncodeToString(encKey.Bytes()), hex.EncodeToString(authKey)
	if e.EncryptionKey != encHex || e.AuthorizationKey != authHex {
		return nil, rejected
	}
	expires := min(c.Now+240, p.ExpiresAt, facts.FreshnessExpiresAt.Unix())
	return json.Marshal(Verified{encHex, authHex, c.Origin, m.GatewayImageDigest, m.SourceRepository, m.SourceRevision, m.ConfigRepository, m.ConfigDigest, m.Generation, p.Sequence, p.ExpiresAt, expires})
}
