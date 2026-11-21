// Package acctest holds the tooling acceptance tests need: a throwaway certificate
// authority, a SQL Server container, log helpers, and a sign-in proxy. It is imported
// only from test files and never ends up in the provider binary.
package acctest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Certs is a per-run certificate authority and a server certificate for localhost.
type Certs struct {
	// CAFile is a PEM file holding the authority certificate. Point SSL_CERT_FILE at
	// it so that clients trust the server certificate.
	CAFile string
	// Server is the certificate to present, valid for localhost and 127.0.0.1.
	Server tls.Certificate
	// CAPool holds the authority for clients that take a pool directly.
	CAPool *x509.CertPool
}

// NewCerts generates the authority and the server certificate and writes the
// authority to a file in dir.
func NewCerts(dir string) (*Certs, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "acceptance test authority"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return &Certs{
		CAFile: caFile,
		CAPool: pool,
		Server: tls.Certificate{Certificate: [][]byte{srvDER, caDER}, PrivateKey: srvKey},
	}, nil
}

// HTTPClient returns a client that trusts the per-run authority directly, for unit tests
// that run without SSL_CERT_FILE.
func (c *Certs) HTTPClient() *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: c.CAPool, MinVersion: tls.VersionTLS12}}}
}
