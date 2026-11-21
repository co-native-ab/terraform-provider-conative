package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"strings"
)

// KeyTypes lists the values of key_type.
func KeyTypes() []string {
	return []string{"RSA2048", "RSA3072", "RSA4096", "P256", "P384", "P521"}
}

// KeyProps are the Key Vault key properties of a key type.
type KeyProps struct {
	KTY     string // "RSA" or "EC"
	KeySize int    // RSA only
	Curve   string // EC only
}

// KeyPropsFor maps a key_type to Key Vault key properties.
func KeyPropsFor(keyType string) (KeyProps, error) {
	switch keyType {
	case "RSA2048":
		return KeyProps{KTY: "RSA", KeySize: 2048}, nil
	case "RSA3072":
		return KeyProps{KTY: "RSA", KeySize: 3072}, nil
	case "RSA4096":
		return KeyProps{KTY: "RSA", KeySize: 4096}, nil
	case "P256":
		return KeyProps{KTY: "EC", Curve: "P-256"}, nil
	case "P384":
		return KeyProps{KTY: "EC", Curve: "P-384"}, nil
	case "P521":
		return KeyProps{KTY: "EC", Curve: "P-521"}, nil
	}
	return KeyProps{}, fmt.Errorf("%q must be one of %s", keyType, strings.Join(KeyTypes(), ", "))
}

// ValidateKeyType checks a key_type value.
func ValidateKeyType(s string) error {
	_, err := KeyPropsFor(s)
	return err
}

// KeyTypeOf names the type of a public key. The six supported types read as their
// key_type value; anything else reads as a description such as "RSA 1024" or "EC P-224",
// which never equals a valid key_type.
func KeyTypeOf(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		switch k.N.BitLen() {
		case 2048, 3072, 4096:
			return fmt.Sprintf("RSA%d", k.N.BitLen())
		}
		return fmt.Sprintf("RSA %d", k.N.BitLen())
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return "P256"
		case elliptic.P384():
			return "P384"
		case elliptic.P521():
			return "P521"
		}
		return "EC " + k.Curve.Params().Name
	}
	return fmt.Sprintf("%T", pub)
}

// AccountKeyAlg checks that a key can be the key of an ACME account and returns the
// Key Vault signature algorithm and the hash the digest must use: RSA with a modulus of
// at least 2048 bits signs RS256; P-256, P-384 and P-521 sign ES256, ES384 and ES512.
func AccountKeyAlg(pub crypto.PublicKey) (alg string, hash crypto.Hash, err error) {
	const accepted = "accepted keys are RSA with at least 2048 bits and EC on P-256, P-384 or P-521"
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return "", 0, fmt.Errorf("RSA key of %d bits is not accepted; %s", k.N.BitLen(), accepted)
		}
		return "RS256", crypto.SHA256, nil
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return "ES256", crypto.SHA256, nil
		case elliptic.P384():
			return "ES384", crypto.SHA384, nil
		case elliptic.P521():
			return "ES512", crypto.SHA512, nil
		}
		return "", 0, fmt.Errorf("EC curve %s is not accepted; %s", k.Curve.Params().Name, accepted)
	}
	return "", 0, fmt.Errorf("key type %T is not accepted; %s", pub, accepted)
}
