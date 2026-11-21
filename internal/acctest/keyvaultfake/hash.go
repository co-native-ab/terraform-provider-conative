package keyvaultfake

import "crypto/sha1" //nolint:gosec // x5t is defined as a SHA-1 thumbprint

func sha1Sum(b []byte) []byte {
	s := sha1.Sum(b) //nolint:gosec // see the import
	return s[:]
}
