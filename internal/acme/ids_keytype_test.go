package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
)

func TestVaultURL(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"https://example.vault.azure.net":      "https://example.vault.azure.net",
		"https://Example.vault.azure.net/":     "https://example.vault.azure.net",
		"https://example.vault.azure.net:8443": "https://example.vault.azure.net:8443",
	} {
		if got, err := ParseVaultURL(in); err != nil || got != want {
			t.Errorf("%q: %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{
		"http://example.vault.azure.net", "https://user@example.vault.azure.net", "https://example.vault.azure.net/keys",
		"https://example.vault.azure.net?x=1", "https://example.vault.azure.net#f", "example.vault.azure.net", "",
		// Only vault names under vault.azure.net receive an access token.
		"https://example.vault.azure.com/", "https://vault.azure.net", "https://evilvault.azure.net", "https://example.vault.azure.net.example.com",
		"https://localhost:8443", "https://127.0.0.1", "https://example.vault.usgovcloudapi.net",
	} {
		if _, err := ParseVaultURL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if !VaultURLEqual("https://A.vault.azure.net/", "https://a.vault.azure.net") || VaultURLEqual("https://a.net", "https://b.net") || VaultURLEqual("x", "x") {
		t.Error("VaultURLEqual")
	}
}

func TestKeyAndCertificateIDs(t *testing.T) {
	t.Parallel()
	k, err := ParseKeyID("https://example.vault.azure.net/keys/acme-account/0123456789abcdef")
	if err != nil || k.Name != "acme-account" || k.Version != "0123456789abcdef" || k.Vault != "https://example.vault.azure.net" {
		t.Fatalf("%+v, %v", k, err)
	}
	if _, err := ParseKeyID("https://example.vault.azure.net/keys/acme-account"); err == nil || !strings.Contains(err.Error(), "azurerm_key_vault_key") {
		t.Errorf("versionless: %v", err)
	}
	for _, bad := range []string{
		"https://example.vault.azure.net/keys/a/b/c", "https://example.vault.azure.net/secrets/a/b", "https://example.vault.azure.net/keys/a_b/c",
		"https://example.vault.azure.net/keys/a/b?x", "http://example.vault.azure.net/keys/a/b",
	} {
		if _, err := ParseKeyID(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, bad := range []string{"https://example.vault.azure.com/keys/a/b", "https://localhost/keys/a/b", "https://example.vault.azure.net.example.com/keys/a/b"} {
		if _, err := ParseKeyID(bad); err == nil {
			t.Errorf("key ID %q accepted", bad)
		}
	}
	for _, bad := range []string{"https://example.vault.azure.com/certificates/a", "https://localhost/certificates/a"} {
		if _, _, err := ParseCertificateImportID(bad); err == nil {
			t.Errorf("import ID %q accepted", bad)
		}
	}
	v, n, err := ParseCertificateImportID("https://example.vault.azure.net/certificates/example-com")
	if err != nil || v != "https://example.vault.azure.net" || n != "example-com" {
		t.Fatalf("%q %q %v", v, n, err)
	}
	if _, _, err := ParseCertificateImportID("https://example.vault.azure.net/certificates/example-com/0123"); err == nil {
		t.Error("versioned import ID accepted")
	}
	if CertificateID("https://v", "n") != "https://v/certificates/n" || SecretID("https://v", "n") != "https://v/secrets/n" {
		t.Error("formatting")
	}
	for _, ok := range []string{"a", "example-com", strings.Repeat("a", 127)} {
		if ValidateCertificateName(ok) != nil {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", "a_b", "a.b", "a/b", strings.Repeat("a", 128)} {
		if ValidateCertificateName(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestRegistrationID(t *testing.T) {
	t.Parallel()
	id := RegistrationID("https://acme.example.org/directory", "https://example.vault.azure.net/keys/k/v1")
	s, k, err := ParseRegistrationID(id)
	if err != nil || s != "https://acme.example.org/directory" || k.Name != "k" {
		t.Fatalf("%q %+v %v", s, k, err)
	}
	for _, bad := range []string{"", "x", id + "|more", "http://acme.example.org|https://v/keys/k/v1", "https://acme.example.org|https://v/keys/k"} {
		if _, _, err := ParseRegistrationID(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, bad := range []string{"http://x", "https://u@x", "https://x#f", "https://x?q", "https://x|y"} {
		if ValidateServerURL(bad) == nil {
			t.Errorf("server URL %q accepted", bad)
		}
	}
	if ValidateServerURL("https://acme-v02.api.letsencrypt.org/directory") != nil {
		t.Error("directory rejected")
	}
}

func TestSmallValidators(t *testing.T) {
	t.Parallel()
	if ValidateSubscriptionID("00000000-0000-0000-0000-000000000000") != nil || ValidateSubscriptionID("nope") == nil {
		t.Error("subscription id")
	}
	if ValidateResourceGroup("dns_(1)") != nil || ValidateResourceGroup("a.") == nil || ValidateResourceGroup("") == nil {
		t.Error("resource group")
	}
	if ValidateEmail("a@example.com") != nil || ValidateEmail("a b@example.com") == nil || ValidateEmail("a@b,c@d") == nil {
		t.Error("email")
	}
}

func TestKeyTypes(t *testing.T) {
	t.Parallel()
	want := map[string]KeyProps{
		"RSA2048": {KTY: "RSA", KeySize: 2048}, "RSA3072": {KTY: "RSA", KeySize: 3072}, "RSA4096": {KTY: "RSA", KeySize: 4096},
		"P256": {KTY: "EC", Curve: "P-256"}, "P384": {KTY: "EC", Curve: "P-384"}, "P521": {KTY: "EC", Curve: "P-521"},
	}
	for kt, p := range want {
		if got, err := KeyPropsFor(kt); err != nil || got != p {
			t.Errorf("%s: %+v %v", kt, got, err)
		}
	}
	if _, err := KeyPropsFor("RSA1024"); err == nil || !strings.Contains(err.Error(), "P521") {
		t.Errorf("unknown key type: %v", err)
	}

	for kt, curve := range map[string]elliptic.Curve{"P256": elliptic.P256(), "P384": elliptic.P384(), "P521": elliptic.P521(), "EC P-224": elliptic.P224()} {
		k, _ := ecdsa.GenerateKey(curve, rand.Reader)
		if got := KeyTypeOf(&k.PublicKey); got != kt {
			t.Errorf("%s read as %s", kt, got)
		}
	}
	for bits, want := range map[int]string{1024: "RSA 1024", 2048: "RSA2048"} {
		k, _ := rsa.GenerateKey(rand.Reader, bits) //nolint:gosec // a small key is the point of the test
		if got := KeyTypeOf(&k.PublicKey); got != want {
			t.Errorf("RSA %d read as %s", bits, got)
		}
	}

	k256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if alg, _, err := AccountKeyAlg(&k256.PublicKey); err != nil || alg != "ES256" {
		t.Errorf("%s %v", alg, err)
	}
	k224, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if _, _, err := AccountKeyAlg(&k224.PublicKey); err == nil || !strings.Contains(err.Error(), "accepted keys") {
		t.Errorf("P-224: %v", err)
	}
	small, _ := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // a small key is the point of the test
	if _, _, err := AccountKeyAlg(&small.PublicKey); err == nil {
		t.Error("RSA 1024 accepted")
	}
	big, _ := rsa.GenerateKey(rand.Reader, 2048)
	if alg, _, err := AccountKeyAlg(&big.PublicKey); err != nil || alg != "RS256" {
		t.Errorf("%s %v", alg, err)
	}
}
