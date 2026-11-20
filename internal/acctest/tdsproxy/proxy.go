// Package tdsproxy is a small TDS sign-in proxy for acceptance tests.
//
// Azure SQL Database accepts a Microsoft Entra access token in the LOGIN7 message
// (federated authentication, "security token" library); a SQL Server container does
// not. The proxy accepts that token login from the provider, checks the token against
// the one it was configured with, signs in to the container with SQL authentication
// on the client's behalf, and then relays every packet unchanged.
//
// The proxy knows nothing about Entra users or any other Azure behaviour: it never
// rewrites a query or a result, and it never logs, stores or echoes the token.
package tdsproxy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Config configures a Proxy.
type Config struct {
	ListenAddr   string          // for example "127.0.0.1:0"
	Certificate  tls.Certificate // presented to clients
	Token        string          // the only access token that is accepted
	UpstreamAddr string          // the SQL Server container, "127.0.0.1:port"
	UpstreamUser string          // SQL authentication user, for example "sa"
	UpstreamPass string
}

// Proxy is a running sign-in proxy.
type Proxy struct {
	cfg    Config
	ln     net.Listener
	reject atomic.Bool

	failMu     sync.Mutex
	failNumber int32
	failLeft   int

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
	wg     sync.WaitGroup
}

// Start begins listening and serving.
func Start(cfg Config) (*Proxy, error) {
	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return nil, err
	}
	p := &Proxy{cfg: cfg, ln: ln, conns: map[net.Conn]struct{}{}}
	p.wg.Add(1)
	go p.serve()
	return p, nil
}

// Addr returns the address the proxy listens on, "127.0.0.1:port".
func (p *Proxy) Addr() string { return p.ln.Addr().String() }

// RejectAll makes the proxy refuse every sign-in with error 18456 while on is true.
func (p *Proxy) RejectAll(on bool) { p.reject.Store(on) }

// FailLogins makes the proxy answer the next count sign-ins with a SQL Server error of
// the given number, after the token has been accepted, as a server does while it is
// briefly unavailable. It lets tests exercise how a client reacts to a transient
// error. It changes nothing else about the proxy: no error text or behaviour of any
// particular service is emulated.
func (p *Proxy) FailLogins(number int32, count int) {
	p.failMu.Lock()
	p.failNumber, p.failLeft = number, count
	p.failMu.Unlock()
}

func (p *Proxy) injectedFailure() (int32, bool) {
	p.failMu.Lock()
	defer p.failMu.Unlock()
	if p.failLeft <= 0 {
		return 0, false
	}
	p.failLeft--
	return p.failNumber, true
}

// Close stops listening and drops every connection.
func (p *Proxy) Close() error {
	p.mu.Lock()
	p.closed = true
	err := p.ln.Close()
	for c := range p.conns {
		_ = c.Close()
	}
	p.mu.Unlock()
	p.wg.Wait()
	return err
}

func (p *Proxy) serve() {
	defer p.wg.Done()
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		if !p.track(c) {
			_ = c.Close()
			return
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer p.untrack(c)
			p.handle(c)
		}()
	}
}

func (p *Proxy) track(c net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	p.conns[c] = struct{}{}
	return true
}

func (p *Proxy) untrack(c net.Conn) {
	_ = c.Close()
	p.mu.Lock()
	delete(p.conns, c)
	p.mu.Unlock()
}

// handle serves one client connection. Errors end the connection silently: a test
// that wants to see a failure sees it from the client's side.
func (p *Proxy) handle(client net.Conn) {
	_ = client.SetDeadline(time.Now().Add(30 * time.Second))

	secure, ok := p.negotiate(client)
	if !ok {
		return
	}
	typ, msg, err := readMessage(secure)
	if err != nil || typ != typeLogin7 {
		return
	}
	login, err := ParseLogin7(msg)
	if err != nil {
		p.refuse(secure, 4096)
		return
	}
	packetSize := int(login.PacketSize)
	if !p.tokenAccepted(login) {
		p.refuse(secure, packetSize)
		return
	}

	if number, ok := p.injectedFailure(); ok {
		_ = writeMessage(secure, typeReply, loginFailure(number, fmt.Sprintf("The test proxy answered this sign-in with error %d.", number)), packetSize)
		return
	}

	upstream, err := p.signInUpstream(login)
	if err != nil {
		// The container itself is unavailable: the client sees a failed login.
		p.refuse(secure, packetSize)
		return
	}
	defer func() { _ = upstream.Close() }()

	_ = client.SetDeadline(time.Time{})
	relay(secure, upstream)
}

// negotiate answers the client's PRELOGIN and completes the TLS handshake inside TDS
// packets. Encryption is never off: a client that does not support it is told that it
// is required and disconnected.
func (p *Proxy) negotiate(client net.Conn) (*tls.Conn, bool) {
	typ, msg, err := readMessage(client)
	if err != nil || typ != typePrelogin {
		return nil, false
	}
	opts, err := parsePrelogin(msg)
	if err != nil {
		return nil, false
	}
	if enc, ok := opts[plEncryption]; !ok || len(enc) != 1 || enc[0] == encryptNotSup {
		_ = writeMessage(client, typeReply, serverPrelogin(opts, encryptReq), 4096)
		return nil, false
	}
	if err := writeMessage(client, typeReply, serverPrelogin(opts, encryptOn), 4096); err != nil {
		return nil, false
	}

	hc := &handshakeConn{Conn: client, writeType: typeReply}
	conn := tls.Server(hc, &tls.Config{ //nolint:gosec // TLS 1.2 is the highest version that fits the TDS handshake framing
		Certificates: []tls.Certificate{p.cfg.Certificate},
		MinVersion:   tls.VersionTLS12,
		// TLS 1.2 keeps the handshake inside the TDS packets; session tickets would
		// otherwise be written after the switch to raw TLS records.
		MaxVersion:                  tls.VersionTLS12,
		DynamicRecordSizingDisabled: true,
	})
	if err := conn.Handshake(); err != nil {
		return nil, false
	}
	if err := hc.finish(); err != nil {
		return nil, false
	}
	return conn, true
}

func (p *Proxy) tokenAccepted(login *Login7) bool {
	if p.reject.Load() {
		return false
	}
	token, found, err := login.FedAuthToken()
	if err != nil || !found {
		return false
	}
	return TokenMatches(token, p.cfg.Token)
}

func (p *Proxy) refuse(w io.Writer, packetSize int) {
	_ = writeMessage(w, typeReply, loginFailure(18456, "Login failed for user '<token-identified principal>'."), packetSize)
}

// signInUpstream connects to the container, negotiates TLS and sends the client's
// LOGIN7 rebuilt with SQL authentication. The container's login response is not
// read here: it is relayed to the client like any other traffic.
func (p *Proxy) signInUpstream(login *Login7) (*tls.Conn, error) {
	raw, err := net.DialTimeout("tcp", p.cfg.UpstreamAddr, 10*time.Second)
	if err != nil {
		return nil, err
	}
	_ = raw.SetDeadline(time.Now().Add(30 * time.Second))
	fail := func(err error) (*tls.Conn, error) {
		_ = raw.Close()
		return nil, err
	}

	prelogin := buildPrelogin([]preloginOption{
		{plVersion, []byte{0x10, 0x00, 0x10, 0x00, 0x00, 0x00}},
		{plEncryption, []byte{encryptOn}},
		{plInstOpt, []byte{0x00}},
		{plThreadID, []byte{0, 0, 0, 0}},
		{plMARS, []byte{0x00}},
	})
	if err := writeMessage(raw, typePrelogin, prelogin, 4096); err != nil {
		return fail(err)
	}
	typ, msg, err := readMessage(raw)
	if err != nil || typ != typeReply {
		return fail(errors.New("no PRELOGIN response from the server"))
	}
	opts, err := parsePrelogin(msg)
	if err != nil {
		return fail(err)
	}
	if enc := opts[plEncryption]; len(enc) != 1 || (enc[0] != encryptOn && enc[0] != encryptReq) {
		return fail(fmt.Errorf("the server did not agree to encrypt the session"))
	}

	hc := &handshakeConn{Conn: raw, writeType: typePrelogin}
	conn := tls.Client(hc, &tls.Config{
		// The container presents a self-signed certificate. This is test tooling for a
		// container started by the test itself, on a loopback address.
		InsecureSkipVerify:          true, //nolint:gosec // see above
		MinVersion:                  tls.VersionTLS12,
		MaxVersion:                  tls.VersionTLS12,
		DynamicRecordSizingDisabled: true,
	})
	if err := conn.Handshake(); err != nil {
		return fail(err)
	}
	if err := hc.finish(); err != nil {
		return fail(err)
	}

	upstreamLogin := login.WithSQLAuth(p.cfg.UpstreamUser, p.cfg.UpstreamPass)
	if err := writeMessage(conn, typeLogin7, upstreamLogin.Marshal(), int(login.PacketSize)); err != nil {
		return fail(err)
	}
	_ = raw.SetDeadline(time.Time{})
	return conn, nil
}

// relay copies bytes both ways until either side ends. TDS framing is carried inside
// the byte stream, so nothing needs to be parsed; TLS record boundaries are kept
// because each read returns at most one record and is written as one.
func relay(a, b net.Conn) {
	var once sync.Once
	closeBoth := func() {
		_ = a.Close()
		_ = b.Close()
	}
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		once.Do(closeBoth)
		done <- struct{}{}
	}
	go pipe(a, b)
	go pipe(b, a)
	<-done
	<-done
}
