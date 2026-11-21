package acctest

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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

// AssertNoSecretInFiles walks dir and fails the test if a regular file whose base name
// matches one of names holds the secret. It returns the number of files it searched,
// so callers can make sure the check was not vacuous.
func AssertNoSecretInFiles(t *testing.T, dir, secret string, names ...string) int {
	t.Helper()
	searched := 0
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		for _, n := range names {
			if ok, _ := filepath.Match(n, d.Name()); !ok {
				continue
			}
			data, err := os.ReadFile(path) //nolint:gosec // walking a directory the test created
			if err != nil {
				return err
			}
			searched++
			if ContainsSecret(data, secret) {
				t.Errorf("%s contains the secret", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return searched
}

// AssertLogContains fails the test if the file does not contain the text.
func AssertLogContains(t *testing.T, path, text string) {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // the path is created by the test
	if err != nil {
		t.Fatalf("cannot read %s: %v", path, err)
	}
	if !bytes.Contains(data, []byte(text)) {
		t.Errorf("%s does not contain %q", path, text)
	}
}

// privateKeyForms are the forms in which a DER private key could leak into a file: the
// raw bytes, base64 (standard and URL) and the PEM body.
func privateKeyForms(der []byte) map[string][]byte {
	std := base64.StdEncoding.EncodeToString(der)
	return map[string][]byte{
		"raw":          der,
		"base64":       []byte(std),
		"base64 (url)": []byte(base64.RawURLEncoding.EncodeToString(der)),
		"PEM body":     []byte(strings.ReplaceAll(wrap64(std), "\r", "")),
	}
}

// wrap64 wraps base64 text at 64 columns, as PEM does.
func wrap64(s string) string {
	var b strings.Builder
	for len(s) > 64 {
		b.WriteString(s[:64])
		b.WriteByte('\n')
		s = s[64:]
	}
	b.WriteString(s)
	return b.String()
}

// ContainsPrivateKey reports whether data holds a private key marker or any of the keys
// in one of the forms checked.
func ContainsPrivateKey(data []byte, keys [][]byte) bool {
	if bytes.Contains(data, []byte("PRIVATE KEY-----")) {
		return true
	}
	for _, k := range keys {
		for _, form := range privateKeyForms(k) {
			if len(form) > 0 && bytes.Contains(data, form) {
				return true
			}
		}
	}
	return false
}

// AssertPrivateKeysAbsent fails the test if the file is empty or holds a private key in
// one of the forms checked.
func AssertPrivateKeysAbsent(t *testing.T, path string, keys [][]byte) {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // the path is created by the test
	if err != nil {
		t.Fatalf("cannot read %s: %v", path, err)
	}
	if len(data) == 0 {
		t.Fatalf("%s is empty, so the check would prove nothing", path)
	}
	if ContainsPrivateKey(data, keys) {
		t.Errorf("%s contains a private key", path)
	}
}

// AssertNoPrivateKeyInFiles walks dir and fails the test if a regular file whose base
// name matches one of names holds a private key. It returns the number of files it
// searched.
func AssertNoPrivateKeyInFiles(t *testing.T, dir string, keys [][]byte, names ...string) int {
	t.Helper()
	searched := 0
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		for _, n := range names {
			if ok, _ := filepath.Match(n, d.Name()); !ok {
				continue
			}
			data, err := os.ReadFile(path) //nolint:gosec // walking a directory the test created
			if err != nil {
				return err
			}
			searched++
			if ContainsPrivateKey(data, keys) {
				t.Errorf("%s contains a private key", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return searched
}
