package keyvault_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"strings"
	"testing"

	"github.com/co-native-ab/terraform-provider-conative/internal/acctest"
	"github.com/co-native-ab/terraform-provider-conative/internal/acctest/keyvaultfake"
	"github.com/co-native-ab/terraform-provider-conative/internal/acme/keyvault"
)

const token = "a-test-token-that-must-never-appear-in-an-error"

func start(t *testing.T) (*keyvaultfake.Server, *keyvault.Client, *acctest.Certs) {
	t.Helper()
	certs, err := acctest.NewCerts(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv, err := keyvaultfake.Start(certs.Server, token)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	c, err := keyvault.New(srv.URL, token, certs.HTTPClient())
	if err != nil {
		t.Fatal(err)
	}
	return srv, c, certs
}

func keyRef(t *testing.T, id string) (name, version string) {
	t.Helper()
	parts := strings.Split(id, "/")
	return parts[len(parts)-2], parts[len(parts)-1]
}

func TestSignerSignsWithKeysThatStayInTheVault(t *testing.T) {
	srv, c, _ := start(t)
	ctx := context.Background()
	for _, kind := range []string{"RSA2048", "P256", "P384", "P521"} {
		name, version := keyRef(t, srv.AddKey("k-"+strings.ToLower(kind), kind, true))
		s, err := keyvault.NewSigner(ctx, c, name, version)
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		hash := crypto.SHA256
		switch kind {
		case "P384":
			hash = crypto.SHA384
		case "P521":
			hash = crypto.SHA512
		}
		var digest []byte
		switch hash {
		case crypto.SHA256:
			d := sha256.Sum256([]byte("message"))
			digest = d[:]
		case crypto.SHA384:
			d := sha512.Sum384([]byte("message"))
			digest = d[:]
		default:
			d := sha512.Sum512([]byte("message"))
			digest = d[:]
		}
		sig, err := s.Sign(nil, digest, hash)
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		switch pub := s.Public().(type) {
		case *rsa.PublicKey:
			if err := rsa.VerifyPKCS1v15(pub, hash, digest, sig); err != nil {
				t.Errorf("%s: %v", kind, err)
			}
		case *ecdsa.PublicKey:
			if !ecdsa.VerifyASN1(pub, digest, sig) {
				t.Errorf("%s: the signature does not verify", kind)
			}
		}
	}
}

func TestSignerRefusesBeforeAnyRequest(t *testing.T) {
	srv, c, _ := start(t)
	ctx := context.Background()
	name, version := keyRef(t, srv.AddKey("k", "P256", true))
	s, err := keyvault.NewSigner(ctx, c, name, version)
	if err != nil {
		t.Fatal(err)
	}
	mark := srv.Journal.Mark()
	d384 := sha512.Sum384(nil)
	if _, err := s.Sign(nil, d384[:], crypto.SHA384); err == nil {
		t.Error("a SHA-384 digest was accepted for P-256")
	}
	if _, err := s.Sign(nil, []byte("short"), crypto.SHA256); err == nil {
		t.Error("a digest of the wrong length was accepted")
	}
	if n := len(srv.Journal.Since(mark)); n != 0 {
		t.Errorf("%d requests were made for refused signatures", n)
	}

	for _, bad := range []struct{ kind, want string }{{"P256K", "not accepted"}, {"RSA1024", "not accepted"}} {
		n, v := keyRef(t, srv.AddKey("bad-"+strings.ToLower(bad.kind), bad.kind, true))
		if _, err := keyvault.NewSigner(ctx, c, n, v); err == nil || !strings.Contains(err.Error(), bad.want) {
			t.Errorf("%s: %v", bad.kind, err)
		}
	}
	n, v := keyRef(t, srv.AddKey("no-sign", "P256", false))
	if _, err := keyvault.NewSigner(ctx, c, n, v); err == nil || !strings.Contains(err.Error(), "sign") {
		t.Errorf("a key without the sign operation: %v", err)
	}
}

func TestErrorsNameStatusCodeAndMessageButNeverTheToken(t *testing.T) {
	srv, c, certs := start(t)
	ctx := context.Background()
	_, err := c.GetKey(ctx, "missing", "v1")
	var ae *keyvault.APIError
	if !errors.As(err, &ae) || ae.Status != 404 || ae.Code != "KeyNotFound" || !errors.Is(err, keyvault.ErrNotFound) {
		t.Fatalf("a missing key: %#v", err)
	}
	if !strings.Contains(err.Error(), "404") || !strings.Contains(err.Error(), "KeyNotFound") {
		t.Errorf("the error lacks status or code: %v", err)
	}

	srv.SetFailure(503)
	if _, err = c.GetCertificate(ctx, "x"); err == nil || strings.Contains(err.Error(), token) || !strings.Contains(err.Error(), "503") {
		t.Errorf("a failing vault: %v", err)
	}
	srv.SetFailure(0)

	wrong, _ := keyvault.New(srv.URL, "another-token", certs.HTTPClient())
	if _, err = wrong.GetCertificate(ctx, "x"); err == nil || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "another-token") {
		t.Errorf("a wrong token: %v", err)
	}
}

func TestBaseURLMustBeHTTPS(t *testing.T) {
	if _, err := keyvault.New("http://example.vault.azure.net", token, nil); err == nil {
		t.Error("an http URL was accepted")
	}
	if _, err := keyvault.New("", token, nil); err == nil {
		t.Error("an empty URL was accepted")
	}
}
