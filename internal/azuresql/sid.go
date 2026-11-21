package azuresql

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidEntraID is returned for Entra IDs that are not canonical GUIDs.
var ErrInvalidEntraID = errors.New("must be a GUID such as 00000000-0000-0000-0000-000000000000")

// ParseEntraID validates a canonical GUID (8-4-4-4-12 hexadecimal digits, no braces)
// and returns it in lower case.
func ParseEntraID(s string) (string, error) {
	if len(s) != 36 {
		return "", ErrInvalidEntraID
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return "", ErrInvalidEntraID
			}
		default:
			if !isHex(r) {
				return "", ErrInvalidEntraID
			}
		}
	}
	return strings.ToLower(s), nil
}

func isHex(r rune) bool {
	return r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F'
}

// SIDFromEntraID derives the 16-byte security identifier of an Entra principal from
// its GUID: the bytes of the GUID in the order SQL Server stores a uniqueidentifier
// (the first three groups little-endian, the rest as written).
func SIDFromEntraID(entraID string) ([]byte, error) {
	canonical, err := ParseEntraID(entraID)
	if err != nil {
		return nil, err
	}
	plain, err := hex.DecodeString(strings.ReplaceAll(canonical, "-", ""))
	if err != nil {
		return nil, ErrInvalidEntraID
	}
	return guidSwap(plain), nil
}

// EntraIDFromSID is the reverse of SIDFromEntraID. It reports false unless the
// identifier is exactly 16 bytes.
func EntraIDFromSID(sid []byte) (string, bool) {
	if len(sid) != 16 {
		return "", false
	}
	b := guidSwap(sid)
	h := hex.EncodeToString(b)
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32]), true
}

// guidSwap converts between the textual byte order of a GUID and the order of a
// uniqueidentifier. The operation is its own inverse.
func guidSwap(in []byte) []byte {
	out := make([]byte, 16)
	copy(out, in)
	out[0], out[1], out[2], out[3] = in[3], in[2], in[1], in[0]
	out[4], out[5] = in[5], in[4]
	out[6], out[7] = in[7], in[6]
	return out
}

// SIDHex formats a security identifier as 0x followed by upper-case hexadecimal
// digits, the form SQL Server uses for binary literals.
func SIDHex(sid []byte) string {
	return "0x" + strings.ToUpper(hex.EncodeToString(sid))
}

// SIDLiteral returns the T-SQL binary literal for the security identifier derived
// from entraID. It is built from parsed bytes only, never from the input text.
func SIDLiteral(entraID string) (string, error) {
	sid, err := SIDFromEntraID(entraID)
	if err != nil {
		return "", err
	}
	return SIDHex(sid), nil
}
