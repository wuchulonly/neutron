//go:build !tinygo
// +build !tinygo

package tlsx

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func sampleState() *tls.ConnectionState {
	leaf := &x509.Certificate{
		Raw:            []byte("der-bytes-Internet Widgits Pty Ltd-marker"),
		SerialNumber:   big.NewInt(0x1234), // decimal 4660 == hex 12:34
		DNSNames:       []string{"ingress-nginx", "leaf.example"},
		EmailAddresses: []string{"admin@example.com"},
		NotBefore:      time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC),
		NotAfter:       time.Date(2120, 1, 2, 3, 4, 5, 0, time.UTC),
		Subject: pkix.Name{
			CommonName:   "leaf.example",
			Organization: []string{"Internet Widgits Pty Ltd"},
		},
		Issuer: pkix.Name{CommonName: "issuer-cn", Organization: []string{"qax"}},
	}
	return &tls.ConnectionState{
		Version:          0x0303, // tls12
		CipherSuite:      0x1301, // TLS_AES_128_GCM_SHA256
		ServerName:       "leaf.example",
		PeerCertificates: []*x509.Certificate{leaf},
	}
}

func TestFillCertDSLNucleiNamespaceOnly(t *testing.T) {
	data := map[string]interface{}{}
	FillCertDSL(data, sampleState(), "leaf.example")

	if _, ok := data["not_before"].(time.Time); !ok {
		t.Errorf("nuclei not_before must be time.Time, got %T", data["not_before"])
	}
	if data["serial"] != "12:34" {
		t.Errorf("nuclei serial = %v, want colon-hex 12:34", data["serial"])
	}
	if data["tls_version"] != "tls12" {
		t.Errorf("tls_version = %v, want tls12", data["tls_version"])
	}
	if data["cipher"] != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("cipher = %v", data["cipher"])
	}
	if data["mismatched"] != false {
		t.Errorf("mismatched should be false for matching SNI, got %v", data["mismatched"])
	}
	if data["expired"] != false {
		t.Errorf("expired should be false for far-future not_after, got %v", data["expired"])
	}
	fp, ok := data["fingerprint_hash"].(FingerprintHash)
	if !ok || len(fp.SHA256) != 64 || len(fp.SHA1) != 40 || len(fp.MD5) != 32 {
		t.Errorf("fingerprint_hash shape wrong: %#v", data["fingerprint_hash"])
	}

	for _, key := range []string{
		"cert_subject", "cert_issuer", "cert_not_before", "cert_not_after",
		"cert_dnsnames", "cert_serial", "cert_common_name", "cert_organization",
		"raw_cert", "validity", "trusted",
	} {
		if _, ok := data[key]; ok {
			t.Errorf("non-nuclei compatibility field %q should not be populated: %+v", key, data)
		}
	}
}

func TestFillCertDSLNoCert(t *testing.T) {
	data := map[string]interface{}{}
	FillCertDSL(data, nil, "")
	if len(data) != 0 {
		t.Errorf("expected no keys for nil state, got %v", data)
	}
	FillCertDSL(data, &tls.ConnectionState{}, "")
	if len(data) != 0 {
		t.Errorf("expected no keys for empty chain, got %v", data)
	}
}

func TestFillCertDSLEmptySNINoMismatch(t *testing.T) {
	data := map[string]interface{}{}
	FillCertDSL(data, sampleState(), "") // empty SNI must not flag mismatch
	if data["mismatched"] != false {
		t.Errorf("empty SNI should not be marked mismatched, got %v", data["mismatched"])
	}
}

func TestUntrustedSelfSignedFromSample(t *testing.T) {
	// sampleState() is a synthetic self-signed leaf with random DER. It must
	// fail x509.Verify against the system root pool — that's the whole point
	// of the untrusted flag: anything a normal HTTPS client would reject.
	data := map[string]interface{}{}
	FillCertDSL(data, sampleState(), "leaf.example")
	if data["untrusted"] != true {
		t.Errorf("synthetic self-signed leaf should be untrusted=true, got %v", data["untrusted"])
	}
}

func TestUntrustedNoState(t *testing.T) {
	// Defensive: nil/empty state must not crash and must report false.
	if IsUntrusted(nil, "x") {
		t.Errorf("nil state should not be untrusted")
	}
	if IsUntrusted(&tls.ConnectionState{}, "x") {
		t.Errorf("empty peer cert list should not be untrusted")
	}
}

func TestRevokedNoState(t *testing.T) {
	// Defensive: same shape as untrusted — no peer certs means we have nothing
	// to check, so report not-revoked (soft-fail by design).
	if IsRevoked(nil) {
		t.Errorf("nil state should not be revoked")
	}
	if IsRevoked(&tls.ConnectionState{}) {
		t.Errorf("empty peer cert list should not be revoked")
	}
}

func TestRevokedKeyPresent(t *testing.T) {
	data := map[string]interface{}{}
	FillCertDSL(data, sampleState(), "leaf.example")
	_, ok := data["revoked"].(bool)
	if !ok {
		t.Fatalf("revoked must be bool, got %T (%v)", data["revoked"], data["revoked"])
	}
}

func TestIsRevokedSoftFail(t *testing.T) {
	if IsRevoked(nil) {
		t.Errorf("nil state must soft-fail to false")
	}
	if IsRevoked(&tls.ConnectionState{}) {
		t.Errorf("empty peer cert list must soft-fail to false")
	}
}
