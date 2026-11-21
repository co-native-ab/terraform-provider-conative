package acmefake

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

type flattenedJWS struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type protectedHeader struct {
	Alg   string          `json:"alg"`
	Nonce string          `json:"nonce"`
	URL   string          `json:"url"`
	JWK   json.RawMessage `json:"jwk"`
	KID   string          `json:"kid"`
}

var b64 = base64.RawURLEncoding

// parseJWK builds a public key and its RFC 7638 thumbprint from a JWK.
func parseJWK(raw json.RawMessage) (crypto.PublicKey, string, error) {
	var k struct{ KTY, N, E, Crv, X, Y string }
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, "", err
	}
	switch k.KTY {
	case "RSA":
		n, err1 := b64.DecodeString(k.N)
		e, err2 := b64.DecodeString(k.E)
		if err1 != nil || err2 != nil {
			return nil, "", errors.New("invalid RSA parameters")
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		canon := fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, k.E, k.N)
		return pub, thumbprint(canon), nil
	case "EC":
		curve := map[string]elliptic.Curve{"P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521()}[k.Crv]
		if curve == nil {
			return nil, "", fmt.Errorf("unsupported curve %q", k.Crv)
		}
		x, err1 := b64.DecodeString(k.X)
		y, err2 := b64.DecodeString(k.Y)
		if err1 != nil || err2 != nil {
			return nil, "", errors.New("invalid EC parameters")
		}
		size := (curve.Params().BitSize + 7) / 8
		if len(x) > size || len(y) > size {
			return nil, "", errors.New("invalid EC parameters")
		}
		point := append([]byte{4}, append(padTo(x, size), padTo(y, size)...)...)
		pub, err := ecdsa.ParseUncompressedPublicKey(curve, point)
		if err != nil {
			return nil, "", errors.New("the EC point is not on the curve")
		}
		canon := fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, k.Crv, k.X, k.Y)
		return pub, thumbprint(canon), nil
	}
	return nil, "", fmt.Errorf("unsupported key type %q", k.KTY)
}

func thumbprint(canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	return b64.EncodeToString(sum[:])
}

// verify checks the signature of a JWS against a public key.
func verify(pub crypto.PublicKey, alg string, j flattenedJWS) error {
	sig, err := b64.DecodeString(j.Signature)
	if err != nil {
		return errors.New("the signature is not base64url")
	}
	input := []byte(j.Protected + "." + j.Payload)
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if alg != "RS256" {
			return fmt.Errorf("algorithm %s does not fit an RSA key", alg)
		}
		sum := sha256.Sum256(input)
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, sum[:], sig)
	case *ecdsa.PublicKey:
		var digest []byte
		var size int
		switch {
		case alg == "ES256" && k.Curve == elliptic.P256():
			s := sha256.Sum256(input)
			digest, size = s[:], 32
		case alg == "ES384" && k.Curve == elliptic.P384():
			s := sha512.Sum384(input)
			digest, size = s[:], 48
		case alg == "ES512" && k.Curve == elliptic.P521():
			s := sha512.Sum512(input)
			digest, size = s[:], 66
		default:
			return fmt.Errorf("algorithm %s does not fit this EC key", alg)
		}
		if len(sig) != 2*size {
			return fmt.Errorf("an %s signature is %d bytes, got %d", alg, 2*size, len(sig))
		}
		if !ecdsa.Verify(k, digest, new(big.Int).SetBytes(sig[:size]), new(big.Int).SetBytes(sig[size:])) {
			return errors.New("the signature does not verify")
		}
		return nil
	}
	return errors.New("unsupported key")
}

func padTo(b []byte, size int) []byte {
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
