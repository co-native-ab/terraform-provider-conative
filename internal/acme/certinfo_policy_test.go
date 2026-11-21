package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // matches the thumbprint under test
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

type leafOptions struct {
	cn   string
	dns  []string
	ips  []net.IP
	key  crypto.Signer
	days int
}

func testCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, key
}

func leaf(t *testing.T, o leafOptions) []byte {
	t.Helper()
	ca, caKey := testCA(t)
	if o.key == nil {
		o.key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if o.days == 0 {
		o.days = 90
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: o.cn}, DNSNames: o.dns, IPAddresses: o.ips,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Duration(o.days) * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, o.key.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestInspect(t *testing.T) {
	t.Parallel()
	der := leaf(t, leafOptions{cn: "Example.com", dns: []string{"EXAMPLE.com", "*.Example.com", "*.example.com", "a.example.com"}})
	info, err := Inspect(der)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha1.Sum(der) //nolint:gosec // matches the thumbprint under test
	if info.Thumbprint != strings.ToUpper(hex.EncodeToString(sum[:])) {
		t.Errorf("thumbprint %s", info.Thumbprint)
	}
	if info.CommonName != "example.com" || strings.Join(info.SANs, ",") != "*.example.com,a.example.com" || info.KeyType != "P256" {
		t.Errorf("%+v", info)
	}
	if !strings.HasPrefix(info.PEM, "-----BEGIN CERTIFICATE-----") || !strings.HasSuffix(info.NotAfterString(), "Z") {
		t.Errorf("pem or not_after: %s", info.NotAfterString())
	}
	only, err := Inspect(leaf(t, leafOptions{cn: "example.com"}))
	if err != nil || len(only.SANs) != 0 {
		t.Errorf("no SANs: %+v %v", only, err)
	}
	if _, err := Inspect([]byte("not der")); err == nil {
		t.Error("garbage accepted")
	}
}

func TestInspectForImport(t *testing.T) {
	t.Parallel()
	for _, kt := range []string{"RSA2048", "RSA3072", "RSA4096", "P256", "P384", "P521"} {
		props, _ := KeyPropsFor(kt)
		var key crypto.Signer
		if props.KTY == "RSA" {
			if testing.Short() && props.KeySize > 2048 {
				continue
			}
			key, _ = rsa.GenerateKey(rand.Reader, props.KeySize)
		} else {
			curve := map[string]elliptic.Curve{"P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521()}[props.Curve]
			key, _ = ecdsa.GenerateKey(curve, rand.Reader)
		}
		info, err := InspectForImport(leaf(t, leafOptions{cn: "example.com", dns: []string{"example.com"}, key: key}))
		if err != nil || info.KeyType != kt {
			t.Errorf("%s: %+v %v", kt, info, err)
		}
	}

	// A certificate without a subject common name is adopted; every DNS name is then an
	// alternative name.
	info, err := InspectForImport(leaf(t, leafOptions{dns: []string{"example.com", "*.example.com"}}))
	if err != nil || info.CommonName != "" || !slices.Equal(info.SANs, []string{"*.example.com", "example.com"}) {
		t.Errorf("no common name: %+v %v", info, err)
	}

	rsa1024, _ := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // a small key is the point of the test
	p224, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	rsaOdd := rsaOrNil(t)
	cases := map[string]struct {
		o    leafOptions
		want string
	}{
		"no names at all": {leafOptions{}, "neither a subject common name nor a DNS name"},
		"cn not in names": {leafOptions{cn: "example.com", dns: []string{"www.example.com"}}, "not among"},
		"ip san":          {leafOptions{cn: "example.com", dns: []string{"example.com"}, ips: []net.IP{net.ParseIP("192.0.2.1")}}, "not a DNS name"},
		"single label":    {leafOptions{cn: "example", dns: []string{"example"}}, "not a valid DNS name"},
		"underscore":      {leafOptions{cn: "example.com", dns: []string{"example.com", "a_b.example.com"}}, "not a valid DNS name"},
		"rsa 1024":        {leafOptions{cn: "example.com", dns: []string{"example.com"}, key: rsa1024}, "RSA 1024"},
		"ec p224":         {leafOptions{cn: "example.com", dns: []string{"example.com"}, key: p224}, "EC P-224"},
		"ed25519":         {leafOptions{cn: "example.com", dns: []string{"example.com"}, key: edKey}, "not one of"},
	}
	if rsaOdd != nil {
		cases["rsa 2560"] = struct {
			o    leafOptions
			want string
		}{leafOptions{cn: "example.com", dns: []string{"example.com"}, key: rsaOdd}, "RSA 2560"}
	}
	for name, c := range cases {
		if _, err := InspectForImport(leaf(t, c.o)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want error containing %q, got %v", name, c.want, err)
		}
	}
	if _, err := InspectForImport([]byte("x")); err == nil {
		t.Error("garbage accepted")
	}
}

func rsaOrNil(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	if testing.Short() {
		return nil
	}
	// A size between the supported ones is as unsupported as 8192 and much cheaper to make.
	k, _ := rsa.GenerateKey(rand.Reader, 2560)
	return k
}

func TestVerifyChain(t *testing.T) {
	t.Parallel()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "example.com"}, DNSNames: []string{"example.com", "*.example.com"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	good := leaf(t, leafOptions{cn: "example.com", dns: []string{"example.com", "*.example.com"}, key: key})
	ids := []string{"*.example.com", "example.com"}
	if err := VerifyChain([][]byte{good}, csrDER, ids); err != nil {
		t.Errorf("right chain rejected: %v", err)
	}
	other := leaf(t, leafOptions{cn: "example.com", dns: []string{"example.com", "*.example.com"}})
	for name, c := range map[string]struct {
		chain [][]byte
		ids   []string
	}{
		"other key":    {[][]byte{other}, ids},
		"missing name": {[][]byte{good}, append([]string{"x.example.com"}, ids...)},
		"extra name":   {[][]byte{good}, ids[:1]},
		"empty chain":  {nil, ids},
		"unparsable":   {[][]byte{good, []byte("junk")}, ids},
	} {
		if err := VerifyChain(c.chain, csrDER, c.ids); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestCreatePolicyAndPrepare(t *testing.T) {
	t.Parallel()
	p, err := CreatePolicy("example.com", []string{"example.com", "*.example.com"}, "RSA4096")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(p)
	want := `{"policy":{"key_props":{"exportable":true,"kty":"RSA","key_size":4096,"reuse_key":false},"secret_props":{"contentType":"application/x-pkcs12"},` +
		`"x509_props":{"subject":"CN=example.com","sans":{"dns_names":["example.com","*.example.com"]}},"issuer":{"name":"Unknown"},"lifetime_actions":[]},"attributes":{"enabled":true}}`
	if string(got) != want {
		t.Errorf("RSA body:\n%s\nwant\n%s", got, want)
	}
	p, _ = CreatePolicy("example.com", []string{"example.com"}, "P384")
	got, _ = json.Marshal(p)
	if !strings.Contains(string(got), `"kty":"EC","crv":"P-384"`) || strings.Contains(string(got), "key_size") {
		t.Errorf("EC body: %s", got)
	}
	if _, err := CreatePolicy("example.com", nil, "bad"); err == nil {
		t.Error("bad key type accepted")
	}

	const id = "https://v.example/certificates/c"
	for name, c := range map[string]struct {
		s        VaultState
		creating bool
		del      bool
		wantErr  string
	}{
		"create fresh":            {VaultState{}, true, false, ""},
		"create existing":         {VaultState{HasIssuedVersion: true}, true, false, id},
		"create leftover pending": {VaultState{HasPending: true, PendingIssuer: "Unknown"}, true, true, ""},
		"update clean":            {VaultState{HasIssuedVersion: true}, false, false, ""},
		"update unknown pending":  {VaultState{HasIssuedVersion: true, HasPending: true, PendingIssuer: "Unknown"}, false, true, ""},
		"update other pending":    {VaultState{HasIssuedVersion: true, HasPending: true, PendingIssuer: "OtherCA"}, false, false, "OtherCA"},
		"other in progress":       {VaultState{HasIssuedVersion: true, HasPending: true, PendingIssuer: "OtherCA", PendingStatus: "inProgress"}, false, false, "OtherCA"},
		"unknown in progress":     {VaultState{HasIssuedVersion: true, HasPending: true, PendingIssuer: "Unknown", PendingStatus: "InProgress"}, false, true, ""},
		"self completed":          {VaultState{HasIssuedVersion: true, HasPending: true, PendingIssuer: "Self", PendingStatus: "completed"}, false, true, ""},
		"other failed":            {VaultState{HasIssuedVersion: true, HasPending: true, PendingIssuer: "OtherCA", PendingStatus: "failed"}, false, true, ""},
		"other cancelled":         {VaultState{HasIssuedVersion: true, HasPending: true, PendingIssuer: "OtherCA", PendingStatus: "cancelled"}, false, true, ""},
		"create self completed":   {VaultState{HasPending: true, PendingIssuer: "Self", PendingStatus: "completed"}, true, true, ""},
	} {
		del, err := PrepareKeyVault(c.s, c.creating, id)
		if del != c.del || (c.wantErr == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.wantErr)) {
			t.Errorf("%s: delete=%v err=%v", name, del, err)
		}
	}
}
