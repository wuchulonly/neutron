//go:build !tinygo
// +build !tinygo

package http

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/chainreactors/neutron/common"
	"github.com/chainreactors/neutron/common/tlsx"
	"github.com/stretchr/testify/require"
)

// TestCertFieldRegistryParity guards the single-source-of-truth invariant:
// every xray cert accessor that the converter accepts must map to a
// nuclei/tlsx key populated by the shared FillCertDSL path.
func TestCertFieldRegistryParity(t *testing.T) {
	data := map[string]interface{}{}
	addTLSCertFields(data, newCertTestResponse(t))

	for sub, key := range common.XrayCertFields {
		if _, ok := data[key]; !ok {
			t.Errorf("XrayCertFields[%q] -> %q not populated by addTLSCertFields", sub, key)
		}
	}

	if _, ok := data["not_before"].(time.Time); !ok {
		t.Errorf("nuclei not_before must stay a time.Time, got %T", data["not_before"])
	}
	if data["serial"] != "12:34" {
		t.Errorf("nuclei serial must be colon-hex, got %v", data["serial"])
	}
	for _, key := range []string{"cert_not_before", "cert_serial", "cert_subject", "raw_cert"} {
		if _, ok := data[key]; ok {
			t.Errorf("non-nuclei compatibility field %q should not be populated", key)
		}
	}
}

// newCertTestResponse builds an *http.Response whose TLS state carries a leaf
// certificate with known marker fields covering every cert subfield.
func newCertTestResponse(t *testing.T) *http.Response {
	t.Helper()
	leaf := &x509.Certificate{
		Raw:          []byte("der-with-Internet Widgits Pty Ltd-marker"),
		SerialNumber: big.NewInt(0x1234), // decimal 4660 == hex 12:34
		Subject: pkix.Name{
			CommonName:   "hfish.local",
			Organization: []string{"Internet Widgits Pty Ltd"},
		},
		Issuer:    pkix.Name{CommonName: "pa-820", Organization: []string{"qax"}},
		NotBefore: time.Date(2020, 12, 4, 9, 1, 5, 0, time.UTC),
		NotAfter:  time.Date(2120, 12, 4, 9, 1, 5, 0, time.UTC),
		DNSNames:  []string{"ingress-nginx", "hfish.local"},
	}
	return &http.Response{
		TLS: &tls.ConnectionState{
			Version:          0x0303,
			PeerCertificates: []*x509.Certificate{leaf},
		},
	}
}

// TestAddTLSCertFieldsEndToEnd does a real TLS handshake against an httptest
// server and asserts the HTTP response exposes nuclei-style TLS keys via the
// shared tlsx path.
func TestAddTLSCertFieldsEndToEnd(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()
	// httptest's TLS server uses a cert with Org "Acme Co" and SAN example.com.

	req, err := http.NewRequest("GET", server.URL+"/", nil)
	require.NoError(t, err)
	resp, err := server.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	data := map[string]interface{}{}
	addTLSCertFields(data, resp)

	require.Contains(t, data["subject_org"], "Acme Co")
	require.Equal(t, "ctls", data["tls_connection"])
	require.NotEmpty(t, data["tls_version"])
	require.IsType(t, time.Time{}, data["not_before"], "nuclei not_before stays a time.Time")
	require.IsType(t, tlsx.FingerprintHash{}, data["fingerprint_hash"])
	for _, key := range []string{"cert_organization", "cert_serial", "cert_not_before", "raw_cert"} {
		require.NotContains(t, data, key)
	}
}
