package acme

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // the SHA-1 thumbprint is how Key Vault and Azure identify certificates, not a security measure
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Info describes a leaf certificate in the form the resource stores.
type Info struct {
	PEM        string
	NotAfter   time.Time
	Thumbprint string // SHA-1 of the DER, upper-case hexadecimal
	// CommonName is the subject common name in lower case.
	CommonName string
	// SANs are the DNS names in lower case, without duplicates and without the common
	// name, sorted. Empty when the certificate has no other name.
	SANs    []string
	KeyType string
}

// NotAfterString formats the expiry as RFC 3339 in UTC.
func (i Info) NotAfterString() string { return i.NotAfter.UTC().Format(time.RFC3339) }

// Inspect describes a DER certificate. It is lenient about the key: an unsupported key
// reads as a description such as "RSA 1024".
func Inspect(der []byte) (Info, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return Info{}, fmt.Errorf("the certificate cannot be parsed: %w", err)
	}
	cn := strings.ToLower(cert.Subject.CommonName)
	seen := map[string]bool{}
	if cn != "" {
		seen[cn] = true
	}
	var sans []string
	for _, n := range cert.DNSNames {
		n = strings.ToLower(n)
		if !seen[n] {
			seen[n] = true
			sans = append(sans, n)
		}
	}
	slices.Sort(sans)
	sum := sha1.Sum(der) //nolint:gosec // see the import
	return Info{
		PEM:        string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		NotAfter:   cert.NotAfter.UTC(),
		Thumbprint: strings.ToUpper(hex.EncodeToString(sum[:])),
		CommonName: cn,
		SANs:       sans,
		KeyType:    KeyTypeOf(cert.PublicKey),
	}, nil
}

// InspectForImport is the strict form used when an existing certificate is adopted. It
// refuses a certificate whose names or key the resource could not represent, with a
// reason that says what is wrong. A certificate without a subject common name is
// accepted: Info.CommonName is then empty and SANs holds every DNS name.
func InspectForImport(der []byte) (Info, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return Info{}, fmt.Errorf("the certificate cannot be parsed: %w", err)
	}
	if len(cert.IPAddresses) > 0 || len(cert.EmailAddresses) > 0 || len(cert.URIs) > 0 {
		return Info{}, fmt.Errorf("the certificate has a subject alternative name that is not a DNS name (IP address, e-mail address or URI)")
	}
	cn := strings.ToLower(cert.Subject.CommonName)
	if cn == "" && len(cert.DNSNames) == 0 {
		return Info{}, fmt.Errorf("the certificate has neither a subject common name nor a DNS name")
	}
	found := false
	for _, n := range cert.DNSNames {
		n = strings.ToLower(n)
		if err := ValidateIdentifier(n); err != nil {
			return Info{}, fmt.Errorf("the certificate has a name that is not a valid DNS name: %w", err)
		}
		if n == cn {
			found = true
		}
	}
	if cn != "" {
		if err := ValidateIdentifier(cn); err != nil {
			return Info{}, fmt.Errorf("the common name is not a valid DNS name: %w", err)
		}
		if !found {
			return Info{}, fmt.Errorf("the common name %q is not among the certificate's DNS names", cn)
		}
	}
	info, err := Inspect(der)
	if err != nil {
		return Info{}, err
	}
	if err := ValidateKeyType(info.KeyType); err != nil {
		return Info{}, fmt.Errorf("the certificate's key (%s) is not one of %s", info.KeyType, strings.Join(KeyTypes(), ", "))
	}
	return info, nil
}

// VerifyChain checks an issued chain before it is merged: it is not empty, every
// element parses, the leaf's public key equals the key of the signing request and the
// leaf's DNS names equal the identifiers as a set.
func VerifyChain(chain [][]byte, csrDER []byte, identifiers []string) error {
	if len(chain) == 0 {
		return fmt.Errorf("the certificate authority returned an empty chain")
	}
	certs := make([]*x509.Certificate, len(chain))
	for i, d := range chain {
		c, err := x509.ParseCertificate(d)
		if err != nil {
			return fmt.Errorf("certificate %d of the issued chain cannot be parsed: %w", i+1, err)
		}
		certs[i] = c
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return fmt.Errorf("the signing request cannot be parsed: %w", err)
	}
	if !bytes.Equal(certs[0].RawSubjectPublicKeyInfo, csr.RawSubjectPublicKeyInfo) {
		return fmt.Errorf("the issued certificate's key is not the key of the signing request")
	}
	got := make([]string, 0, len(certs[0].DNSNames))
	for _, n := range certs[0].DNSNames {
		got = append(got, strings.ToLower(n))
	}
	want := slices.Clone(identifiers)
	slices.Sort(got)
	slices.Sort(want)
	got, want = slices.Compact(got), slices.Compact(want)
	if !slices.Equal(got, want) {
		return fmt.Errorf("the issued certificate's names (%s) are not the requested names (%s)", strings.Join(got, ", "), strings.Join(want, ", "))
	}
	return nil
}
