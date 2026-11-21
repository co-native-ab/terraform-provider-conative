package keyvault

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/url"
	"slices"
)

// Key is the public part of a Key Vault key.
type Key struct {
	KTY     string   `json:"kty"`
	KeyOps  []string `json:"key_ops"`
	N       string   `json:"n"`
	E       string   `json:"e"`
	Crv     string   `json:"crv"`
	X       string   `json:"x"`
	Y       string   `json:"y"`
	KID     string   `json:"kid"`
	Enabled *bool    `json:"-"`
}

// GetKey reads a versioned key.
func (c *Client) GetKey(ctx context.Context, name, version string) (Key, error) {
	var out struct {
		Key        Key `json:"key"`
		Attributes struct {
			Enabled *bool `json:"enabled"`
		} `json:"attributes"`
	}
	path := "/keys/" + url.PathEscape(name) + "/" + url.PathEscape(version)
	if err := c.do(ctx, "GET", path, "/keys/{name}/{version}", nil, &out); err != nil {
		return Key{}, err
	}
	out.Key.Enabled = out.Attributes.Enabled
	return out.Key, nil
}

// PublicKey builds the public key of the JWK. Only RSA and the curves P-256, P-384 and
// P-521 are understood; anything else (for example P-256K) is an error naming it.
func (k Key) PublicKey() (crypto.PublicKey, error) {
	switch k.KTY {
	case "RSA", "RSA-HSM":
		n, err1 := b64(k.N)
		e, err2 := b64(k.E)
		if err1 != nil || err2 != nil || len(n) == 0 || len(e) == 0 {
			return nil, fmt.Errorf("the key's RSA parameters are not valid")
		}
		ei := new(big.Int).SetBytes(e)
		if !ei.IsInt64() || ei.Int64() > 1<<31-1 {
			return nil, fmt.Errorf("the key's RSA exponent is not valid")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(ei.Int64())}, nil
	case "EC", "EC-HSM":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("the key's curve %q is not accepted; accepted curves are P-256, P-384 and P-521", k.Crv)
		}
		x, err1 := b64(k.X)
		y, err2 := b64(k.Y)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("the key's EC parameters are not valid")
		}
		size := (curve.Params().BitSize + 7) / 8
		if len(x) > size || len(y) > size {
			return nil, fmt.Errorf("the key's EC parameters are not valid")
		}
		point := append([]byte{4}, append(leftPad(x, size), leftPad(y, size)...)...)
		pub, err := ecdsa.ParseUncompressedPublicKey(curve, point)
		if err != nil {
			return nil, fmt.Errorf("the key's EC point is not on the curve")
		}
		return pub, nil
	}
	return nil, fmt.Errorf("the key type %q is not accepted; accepted keys are RSA and EC", k.KTY)
}

// CanSign reports whether the key's permitted operations include sign. A key that lists
// none is taken to permit all.
func (k Key) CanSign() bool { return len(k.KeyOps) == 0 || slices.Contains(k.KeyOps, "sign") }

// Sign signs a digest with a key. alg is RS256, ES256, ES384 or ES512. For RSA the
// result is a PKCS #1 v1.5 signature, for EC the fixed-width r||s form.
func (c *Client) Sign(ctx context.Context, name, version, alg string, digest []byte) ([]byte, error) {
	body := map[string]string{"alg": alg, "value": base64.RawURLEncoding.EncodeToString(digest)}
	var out struct {
		Value string `json:"value"`
	}
	path := "/keys/" + url.PathEscape(name) + "/" + url.PathEscape(version) + "/sign"
	if err := c.do(ctx, "POST", path, "/keys/{name}/{version}/sign", body, &out); err != nil {
		return nil, err
	}
	sig, err := b64(out.Value)
	if err != nil {
		return nil, fmt.Errorf("Key Vault returned a signature that is not base64url: %w", err)
	}
	return sig, nil
}

func b64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(trimPadding(s))
}

func trimPadding(s string) string {
	for len(s) > 0 && s[len(s)-1] == '=' {
		s = s[:len(s)-1]
	}
	return s
}

func leftPad(b []byte, size int) []byte {
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
