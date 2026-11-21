package acme

import (
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
