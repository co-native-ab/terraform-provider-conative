package keyvault

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io"

	"github.com/co-native-ab/terraform-provider-conative/internal/acme"
)

// Signer is a crypto.Signer whose private key stays in Key Vault: every signature is
// made by the vault's sign operation.
type Signer struct {
	ctx     context.Context //nolint:containedctx // crypto.Signer has no context parameter; the signer lives for one operation
	client  *Client
	name    string
	version string
	pub     crypto.PublicKey
	alg     string
	hash    crypto.Hash
	size    int // EC: bytes per coordinate
}

var _ crypto.Signer = (*Signer)(nil)

// NewSigner reads the key and returns a signer for it. It fails when the key cannot be
// an ACME account key (see acme.AccountKeyAlg) or does not permit signing. ctx bounds
// every later signature.
func NewSigner(ctx context.Context, c *Client, name, version string) (*Signer, error) {
	key, err := c.GetKey(ctx, name, version)
	if err != nil {
		return nil, err
	}
	if key.Enabled != nil && !*key.Enabled {
		return nil, fmt.Errorf("the Key Vault key %q is disabled", name)
	}
	if !key.CanSign() {
		return nil, fmt.Errorf("the Key Vault key %q does not permit the sign operation", name)
	}
	pub, err := key.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("the Key Vault key %q: %w", name, err)
	}
	alg, hash, err := acme.AccountKeyAlg(pub)
	if err != nil {
		return nil, fmt.Errorf("the Key Vault key %q: %w", name, err)
	}
	s := &Signer{ctx: ctx, client: c, name: name, version: version, pub: pub, alg: alg, hash: hash}
	if ec, ok := pub.(*ecdsa.PublicKey); ok {
		s.size = (ec.Curve.Params().BitSize + 7) / 8
	}
	return s, nil
}

// Public returns the public key.
func (s *Signer) Public() crypto.PublicKey { return s.pub }

// Sign signs a digest. The hash must be the one of the key's algorithm (SHA-256 for RSA
// and P-256, SHA-384 for P-384, SHA-512 for P-521); anything else fails before a request
// is made. RSA signatures are PKCS #1 v1.5; EC signatures are ASN.1 DER, as the
// interface requires, converted from the vault's fixed-width form.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if _, pss := opts.(*rsa.PSSOptions); pss {
		return nil, fmt.Errorf("RSA-PSS signatures are not supported")
	}
	if opts == nil || opts.HashFunc() != s.hash {
		return nil, fmt.Errorf("the key signs %s digests only", s.hash)
	}
	if len(digest) != s.hash.Size() {
		return nil, fmt.Errorf("a %s digest is %d bytes, got %d", s.hash, s.hash.Size(), len(digest))
	}
	sig, err := s.client.Sign(s.ctx, s.name, s.version, s.alg, digest)
	if err != nil {
		return nil, err
	}
	if s.size == 0 {
		return sig, nil
	}
	return acme.RawToASN1(sig, s.size)
}

// Algorithm returns the signature algorithm of the key.
func (s *Signer) Algorithm() string { return s.alg }
