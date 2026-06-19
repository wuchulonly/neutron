package common

// XrayCertFields maps an xray `response.cert.<sub>` subfield name to the
// nuclei/tlsx data-map key exposed by the HTTP and SSL runtimes. The converter
// uses this map so converted templates depend on nuclei-compatible certificate
// fields instead of neutron-only cert_* aliases.
//
// Aliases (e.g. cn -> common_name) may point at the same data key.
var XrayCertFields = map[string]string{
	"subject":      "subject_dn",
	"issuer":       "issuer_dn",
	"not_before":   "not_before",
	"not_after":    "not_after",
	"dnsnames":     "subject_an",
	"serial":       "serial",
	"common_name":  "subject_cn",
	"cn":           "subject_cn",
	"organization": "subject_org",
	"org":          "subject_org",
}
