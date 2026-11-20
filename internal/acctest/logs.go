package acctest

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"os"
	"testing"
	"unicode/utf16"
)

// EnableTraceLogs turns on the most verbose Terraform, plugin SDK and provider logging
// into a file in dir and returns the file's path. It uses t.Setenv, so the test must
// not be parallel.
func EnableTraceLogs(t *testing.T, dir string) string {
	t.Helper()
	path := dir + "/terraform.log"
	t.Setenv("TF_LOG", "TRACE")
	t.Setenv("TF_LOG_SDK", "TRACE")
	t.Setenv("TF_LOG_PROVIDER", "TRACE")
	t.Setenv("TF_ACC_LOG_PATH", path)
	t.Setenv("TF_LOG_PATH", path)
	return path
}

// AssertSecretAbsent fails the test if the file is empty or contains the secret in its
// plain, UTF-16LE or base64 form.
func AssertSecretAbsent(t *testing.T, path, secret string) {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // the path is created by the test
	if err != nil {
		t.Fatalf("cannot read %s: %v", path, err)
	}
	if len(data) == 0 {
		t.Fatalf("%s is empty, so the check would prove nothing", path)
	}
	for name, form := range secretForms(secret) {
		if bytes.Contains(data, form) {
			t.Errorf("%s contains the secret in %s form", path, name)
		}
	}
}

// ContainsSecret reports whether data holds the secret in any of the forms checked.
func ContainsSecret(data []byte, secret string) bool {
	for _, form := range secretForms(secret) {
		if bytes.Contains(data, form) {
			return true
		}
	}
	return false
}

func secretForms(secret string) map[string][]byte {
	units := utf16.Encode([]rune(secret))
	utf16le := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(utf16le[2*i:], u)
	}
	return map[string][]byte{
		"plain":        []byte(secret),
		"UTF-16LE":     utf16le,
		"base64":       []byte(base64.StdEncoding.EncodeToString([]byte(secret))),
		"base64 (url)": []byte(base64.RawURLEncoding.EncodeToString([]byte(secret))),
	}
}
