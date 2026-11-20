package acctest

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/co-native-ab/terraform-provider-conative/internal/acctest/tdsproxy"
)

// Env is everything an acceptance run needs: a SQL Server container, certificates, a
// sign-in proxy in front of the container, and the token the proxy accepts.
type Env struct {
	Container *Container
	Certs     *Certs
	Proxy     *tdsproxy.Proxy
	// Token is the access token the proxy accepts. It is random per run, as long as a
	// real token, so that tests can search for it.
	Token string
	// WrongToken is a different token of the same shape that the proxy refuses.
	WrongToken string
	// Server is "localhost:port" of the proxy: what a provider configuration uses.
	Server string

	dir string
}

// SetupEnv generates certificates, makes clients trust them by pointing SSL_CERT_FILE
// at the authority (this must happen before anything uses TLS), starts the container
// and the proxy. Callers must call Close.
func SetupEnv(ctx context.Context) (*Env, error) {
	dir, err := os.MkdirTemp("", "conative-acc-")
	if err != nil {
		return nil, err
	}
	e := &Env{dir: dir}
	fail := func(err error) (*Env, error) {
		e.Close()
		return nil, err
	}

	if e.Certs, err = NewCerts(dir); err != nil {
		return fail(err)
	}
	if err := os.Setenv("SSL_CERT_FILE", e.Certs.CAFile); err != nil {
		return fail(err)
	}
	if e.Token, err = randomToken(); err != nil {
		return fail(err)
	}
	if e.WrongToken, err = randomToken(); err != nil {
		return fail(err)
	}
	if e.Container, err = StartContainer(ctx); err != nil {
		return fail(err)
	}
	if e.Proxy, err = e.NewProxy(); err != nil {
		return fail(err)
	}
	e.Server = ServerName(e.Proxy)
	return e, nil
}

// NewProxy starts another sign-in proxy in front of the same container, for tests that
// need to stop one without affecting the others.
func (e *Env) NewProxy() (*tdsproxy.Proxy, error) {
	return tdsproxy.Start(tdsproxy.Config{
		ListenAddr:   "127.0.0.1:0",
		Certificate:  e.Certs.Server,
		Token:        e.Token,
		UpstreamAddr: e.Container.Addr,
		UpstreamUser: "sa",
		UpstreamPass: e.Container.Password,
	})
}

// ServerName returns the provider-facing server name of a proxy, "localhost:port".
func ServerName(p *tdsproxy.Proxy) string {
	_, port, _ := splitAddr(p.Addr())
	return fmt.Sprintf("localhost:%d", port)
}

// Close stops the proxy, removes the container and deletes the temporary files.
func (e *Env) Close() {
	if e.Proxy != nil {
		_ = e.Proxy.Close()
	}
	if e.Container != nil {
		e.Container.Remove()
	}
	if e.dir != "" {
		_ = os.RemoveAll(e.dir)
	}
}

func randomToken() (string, error) {
	b := make([]byte, 1700)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// About 2.2 KB of base64, in the shape of a signed JWT: long enough that the login
	// message spans more than one 4096-byte packet.
	s := base64.RawURLEncoding.EncodeToString(b)
	return "eyJ" + s[:1000] + "." + s[1000:1700] + "." + s[1700:], nil
}
