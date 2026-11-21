package acctest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
)

func TestPrivateKeyDetectionFindsEveryForm(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemBody := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	for name, data := range map[string][]byte{
		"raw":        append([]byte("prefix"), der...),
		"base64":     []byte("x" + base64.StdEncoding.EncodeToString(der) + "y"),
		"base64 url": []byte(base64.RawURLEncoding.EncodeToString(der)),
		"pem":        []byte(pemBody),
	} {
		if !ContainsPrivateKey(data, [][]byte{der}) {
			t.Errorf("%s: the key was not found", name)
		}
	}
	if ContainsPrivateKey([]byte("nothing to see"), [][]byte{der}) {
		t.Error("a false positive")
	}
}
