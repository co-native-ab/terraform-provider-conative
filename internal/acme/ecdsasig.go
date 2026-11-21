package acme

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"math/big"
)

// RawToASN1 converts an ECDSA signature in the fixed-width r||s form Key Vault returns
// (size bytes each) into the ASN.1 DER form crypto.Signer implementations return.
func RawToASN1(raw []byte, size int) ([]byte, error) {
	if size <= 0 || len(raw) != 2*size {
		return nil, fmt.Errorf("an ECDSA signature of this curve is %d bytes, got %d", 2*size, len(raw))
	}
	return asn1.Marshal(struct{ R, S *big.Int }{
		new(big.Int).SetBytes(raw[:size]),
		new(big.Int).SetBytes(raw[size:]),
	})
}

// ASN1ToRaw converts an ASN.1 DER ECDSA signature into fixed-width r||s.
func ASN1ToRaw(der []byte, size int) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil {
		return nil, fmt.Errorf("not an ECDSA signature: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("not an ECDSA signature: %d bytes of trailing data", len(rest))
	}
	if sig.R == nil || sig.S == nil || sig.R.Sign() <= 0 || sig.S.Sign() <= 0 {
		return nil, fmt.Errorf("not an ECDSA signature: r and s must be positive")
	}
	r, s := sig.R.Bytes(), sig.S.Bytes()
	if len(r) > size || len(s) > size {
		return nil, fmt.Errorf("an ECDSA signature value is longer than %d bytes", size)
	}
	return bytes.Join([][]byte{pad(r, size), pad(s, size)}, nil), nil
}

func pad(b []byte, size int) []byte {
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
