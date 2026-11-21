package tdsproxy

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"net"
	"testing"
	"time"
	"unicode/utf16"
)

func TestPacketFraming(t *testing.T) {
	t.Parallel()

	payload := make([]byte, 1500)
	for i := range payload {
		payload[i] = byte(i)
	}
	var buf bytes.Buffer
	if err := writeMessage(&buf, typeLogin7, payload, 512); err != nil {
		t.Fatal(err)
	}
	// 1500 bytes at 504 bytes per packet: three packets, only the last ends the message.
	raw := buf.Bytes()
	if len(raw) != 1500+3*headerLen {
		t.Fatalf("wire size = %d", len(raw))
	}
	if raw[1] != 0 || raw[512+1] != 0 || raw[1024+1] != statusEOM {
		t.Errorf("status bytes = %d %d %d", raw[1], raw[512+1], raw[1024+1])
	}
	typ, got, err := readMessage(&buf)
	if err != nil || typ != typeLogin7 || !bytes.Equal(got, payload) {
		t.Errorf("readMessage = %d, %d bytes, %v", typ, len(got), err)
	}

	// A packet shorter than its header, and a truncated stream, are errors.
	if _, _, _, err := readPacket(bytes.NewReader([]byte{0x10, 1, 0, 4, 0, 0, 0, 0})); err == nil {
		t.Error("length below the header size accepted")
	}
	if _, _, err := readMessage(bytes.NewReader(raw[:700])); err == nil {
		t.Error("truncated message accepted")
	}
	// A message that never ends is cut off.
	var endless bytes.Buffer
	chunk := make([]byte, 4096-headerLen)
	for range maxMessageSize/len(chunk) + 2 {
		_ = writeMessagePacket(&endless, chunk)
	}
	if _, _, err := readMessage(&endless); err == nil {
		t.Error("oversized message accepted")
	}
}

// writeMessagePacket writes one packet without the end-of-message bit.
func writeMessagePacket(buf *bytes.Buffer, payload []byte) error {
	hdr := []byte{typeLogin7, 0, 0, 0, 0, 0, 1, 0}
	binary.BigEndian.PutUint16(hdr[2:], uint16(headerLen+len(payload)))
	buf.Write(hdr)
	buf.Write(payload)
	return nil
}

func TestPreloginRoundTrip(t *testing.T) {
	t.Parallel()

	in := []preloginOption{
		{plVersion, []byte{1, 2, 3, 4, 0, 0}},
		{plEncryption, []byte{encryptOn}},
		{plInstOpt, []byte{0}},
		{plTraceID, bytes.Repeat([]byte{7}, 36)},
		{plFedAuthRequire, []byte{1}},
	}
	opts, err := parsePrelogin(buildPrelogin(in))
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range in {
		if !bytes.Equal(opts[o.token], o.data) {
			t.Errorf("option %#x = %v, want %v", o.token, opts[o.token], o.data)
		}
	}
}

func TestPreloginRejectsMalformed(t *testing.T) {
	t.Parallel()

	good := buildPrelogin([]preloginOption{{plEncryption, []byte{1}}, {plMARS, []byte{0}}})
	// Every strict prefix cuts the option table or its data; none may parse or panic.
	for n := 0; n < len(good); n++ {
		if _, err := parsePrelogin(good[:n]); err == nil {
			t.Errorf("prefix of %d bytes parsed", n)
		}
	}
	bad := []byte{plEncryption, 0x00, 0xFF, 0x00, 0x01, plTerminator, 0x01}
	if _, err := parsePrelogin(bad); err == nil {
		t.Error("option data beyond the message accepted")
	}
	if _, err := parsePrelogin(nil); err == nil {
		t.Error("empty message accepted")
	}
}

func TestServerPrelogin(t *testing.T) {
	t.Parallel()

	withFed, err := parsePrelogin(serverPrelogin(map[byte][]byte{plFedAuthRequire: {1}}, encryptOn))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(withFed[plEncryption], []byte{encryptOn}) {
		t.Errorf("encryption = %v", withFed[plEncryption])
	}
	if !bytes.Equal(withFed[plFedAuthRequire], []byte{1}) {
		t.Errorf("FEDAUTHREQUIRED not echoed: %v", withFed)
	}
	if len(withFed[plVersion]) != 6 {
		t.Errorf("version = %v", withFed[plVersion])
	}

	without, err := parsePrelogin(serverPrelogin(map[byte][]byte{}, encryptReq))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := without[plFedAuthRequire]; ok {
		t.Error("FEDAUTHREQUIRED reported although the client did not ask")
	}
	if !bytes.Equal(without[plEncryption], []byte{encryptReq}) {
		t.Errorf("encryption = %v", without[plEncryption])
	}
}

// driverStyleLogin encodes a LOGIN7 message the way the driver does: the fixed header
// as one struct, the fields in header order, then a pointer DWORD and the feature block.
func driverStyleLogin(database, app, user, password, token string, extraFeature bool) []byte {
	ucs := func(s string) []byte {
		u := utf16.Encode([]rune(s))
		out := make([]byte, 2*len(u))
		for i, c := range u {
			binary.LittleEndian.PutUint16(out[2*i:], c)
		}
		return out
	}
	mangle := func(s string) []byte {
		b := ucs(s)
		for i, c := range b {
			b[i] = ((c << 4) & 0xff) | (c >> 4)
			b[i] ^= 0xA5
		}
		return b
	}
	type header struct {
		Length, TDSVersion, PacketSize, ClientProgVer, ClientPID, ConnectionID uint32
		OptionFlags1, OptionFlags2, TypeFlags, OptionFlags3                    uint8
		ClientTimeZone                                                         int32
		ClientLCID                                                             uint32
		HostNameOffset, HostNameLength                                         uint16
		UserNameOffset, UserNameLength                                         uint16
		PasswordOffset, PasswordLength                                         uint16
		AppNameOffset, AppNameLength                                           uint16
		ServerNameOffset, ServerNameLength                                     uint16
		ExtensionOffset, ExtensionLength                                       uint16
		CtlIntNameOffset, CtlIntNameLength                                     uint16
		LanguageOffset, LanguageLength                                         uint16
		DatabaseOffset, DatabaseLength                                         uint16
		ClientID                                                               [6]byte
		SSPIOffset, SSPILength                                                 uint16
		AtchDBFileOffset, AtchDBFileLength                                     uint16
		ChangePasswordOffset, ChangePasswordLength                             uint16
		SSPILongLength                                                         uint32
	}
	h := header{
		TDSVersion: 0x74000004, PacketSize: 4096, ClientProgVer: 7, ClientPID: 42, ConnectionID: 9,
		OptionFlags1: 0xA0, OptionFlags2: 2, TypeFlags: 0, OptionFlags3: 0, ClientTimeZone: -60, ClientLCID: 1033,
		ClientID: [6]byte{1, 2, 3, 4, 5, 6},
	}
	host, usr, pw := ucs("workstation"), ucs(user), mangle(password)
	appb, srv, ctl, lang, dbb := ucs(app), ucs("example.com"), ucs("go-mssqldb"), ucs(""), ucs(database)
	off := uint16(binary.Size(h))
	h.HostNameOffset, h.HostNameLength = off, uint16(len(host)/2)
	off += uint16(len(host))
	h.UserNameOffset, h.UserNameLength = off, uint16(len(usr)/2)
	off += uint16(len(usr))
	h.PasswordOffset, h.PasswordLength = off, uint16(len(pw)/2)
	off += uint16(len(pw))
	h.AppNameOffset, h.AppNameLength = off, uint16(len(appb)/2)
	off += uint16(len(appb))
	h.ServerNameOffset, h.ServerNameLength = off, uint16(len(srv)/2)
	off += uint16(len(srv))
	h.CtlIntNameOffset, h.CtlIntNameLength = off, uint16(len(ctl)/2)
	off += uint16(len(ctl))
	h.LanguageOffset, h.LanguageLength = off, 0
	h.DatabaseOffset, h.DatabaseLength = off, uint16(len(dbb)/2)
	off += uint16(len(lang) + len(dbb))
	h.SSPIOffset, h.AtchDBFileOffset, h.ChangePasswordOffset = off, off, off

	var feat []byte
	if token != "" {
		tok := ucs(token)
		data := []byte{1<<1 | 1, 0, 0, 0, 0} // security token library, echo
		binary.LittleEndian.PutUint32(data[1:], uint32(len(tok)))
		data = append(data, tok...)
		hdr := []byte{0x02, 0, 0, 0, 0}
		binary.LittleEndian.PutUint32(hdr[1:], uint32(len(data)))
		feat = append(feat, hdr...)
		feat = append(feat, data...)
	}
	if extraFeature {
		feat = append(feat, 0x04, 1, 0, 0, 0, 0x01)
	}
	var tail bytes.Buffer
	if len(feat) > 0 {
		h.OptionFlags3 |= 0x10
		h.ExtensionOffset, h.ExtensionLength = off, 4
		var ptr [4]byte
		binary.LittleEndian.PutUint32(ptr[:], uint32(off)+4)
		tail.Write(ptr[:])
		tail.Write(feat)
		tail.WriteByte(0xFF)
	}
	h.Length = uint32(int(off) + tail.Len())

	var out bytes.Buffer
	_ = binary.Write(&out, binary.LittleEndian, &h)
	for _, b := range [][]byte{host, usr, pw, appb, srv, ctl, lang, dbb, tail.Bytes()} {
		out.Write(b)
	}
	return out.Bytes()
}

func TestParseLogin7DriverLayout(t *testing.T) {
	t.Parallel()

	const token = "eyJhbGciOiJSUzI1NiJ9.payload.signature"
	msg := driverStyleLogin("orders", "terraform-provider-conative", "", "", token, false)
	l, err := ParseLogin7(msg)
	if err != nil {
		t.Fatal(err)
	}
	if l.Database != "orders" || l.AppName != "terraform-provider-conative" || l.HostName != "workstation" ||
		l.ServerName != "example.com" || l.CtlIntName != "go-mssqldb" {
		t.Errorf("strings = %+v", l)
	}
	if l.TDSVersion != 0x74000004 || l.PacketSize != 4096 || l.ClientPID != 42 || l.ClientTimeZone != -60 ||
		l.ClientLCID != 1033 || l.OptionFlags1 != 0xA0 || l.OptionFlags2 != 2 || l.ClientID != [6]byte{1, 2, 3, 4, 5, 6} {
		t.Errorf("numbers = %+v", l)
	}
	carried, found, err := l.FedAuthToken()
	if err != nil || !found {
		t.Fatalf("FedAuthToken = %v, %v, %v", carried, found, err)
	}
	if !TokenMatches(carried, token) {
		t.Error("the carried token does not match")
	}
	if TokenMatches(carried, token+"x") || TokenMatches(carried, token[:len(token)-1]) || TokenMatches(carried, "") {
		t.Error("a different token matched")
	}
}

func TestLogin7WithoutFedAuth(t *testing.T) {
	t.Parallel()

	l, err := ParseLogin7(driverStyleLogin("db", "app", "sa", "p@ssw0rd", "", false))
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := l.FedAuthToken(); found || err != nil {
		t.Errorf("FedAuthToken = %v, %v", found, err)
	}
	if l.UserName != "sa" || l.Password != "p@ssw0rd" {
		t.Errorf("credentials = %q / %q", l.UserName, l.Password)
	}
}

func TestLogin7TruncationNeverPanics(t *testing.T) {
	t.Parallel()

	msg := driverStyleLogin("orders", "app", "", "", "tokentokentoken", true)
	// The token is the last thing before the terminator: every prefix must be handled.
	for n := 0; n < len(msg); n++ {
		l, err := ParseLogin7(msg[:n])
		if err == nil {
			// A prefix that still parses must at least be internally consistent.
			if _, _, ferr := l.FedAuthToken(); ferr != nil {
				t.Errorf("prefix %d parsed but FedAuthToken failed: %v", n, ferr)
			}
		}
	}
	if _, err := ParseLogin7(msg); err != nil {
		t.Errorf("full message: %v", err)
	}
	// Cutting off exactly the 0xFF terminator is an error, not a silent success.
	if _, err := ParseLogin7(msg[:len(msg)-1]); err == nil {
		t.Error("message without the feature terminator accepted")
	}
}

func TestFedAuthTokenAtEndOfPacket(t *testing.T) {
	t.Parallel()

	const token = "last"
	l := &Login7{Features: []Feature{{ID: featureFedAuth, Data: fedAuthData(token, false)}}}
	got, err := ParseLogin7(l.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	carried, found, err := got.FedAuthToken()
	if err != nil || !found || !TokenMatches(carried, token) {
		t.Errorf("FedAuthToken = %v, %v, %v", carried, found, err)
	}
}

func fedAuthData(token string, nonce bool) []byte {
	tok := encodeUCS2(token)
	d := []byte{1 << 1, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(d[1:], uint32(len(tok)))
	d = append(d, tok...)
	if nonce {
		d = append(d, bytes.Repeat([]byte{9}, 32)...)
	}
	return d
}

func TestFedAuthTokenErrors(t *testing.T) {
	t.Parallel()

	for name, data := range map[string][]byte{
		"truncated":     {2, 0, 0},
		"other library": {2 << 1, 0, 0, 0, 0},
		"token overrun": {1 << 1, 0xFF, 0, 0, 0, 'a', 0},
	} {
		l := &Login7{Features: []Feature{{ID: featureFedAuth, Data: data}}}
		if _, found, err := l.FedAuthToken(); err == nil || !found {
			t.Errorf("%s: FedAuthToken = _, %v, %v; want an error", name, found, err)
		}
	}
}

func TestWithSQLAuthKeepsLoginAndDropsFedAuth(t *testing.T) {
	t.Parallel()

	orig, err := ParseLogin7(driverStyleLogin("orders", "terraform-provider-conative", "", "", "secret-token", true))
	if err != nil {
		t.Fatal(err)
	}
	rebuilt := orig.WithSQLAuth("sa", "Passw0rd!")

	got, err := ParseLogin7(rebuilt.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if got.Database != "orders" || got.AppName != "terraform-provider-conative" || got.HostName != "workstation" ||
		got.PacketSize != 4096 || got.TDSVersion != 0x74000004 || got.OptionFlags1 != 0xA0 || got.OptionFlags2 != 2 ||
		got.ClientTimeZone != -60 || got.ClientLCID != 1033 || got.ClientID != orig.ClientID || got.CtlIntName != "go-mssqldb" {
		t.Errorf("fields were not kept: %+v", got)
	}
	if got.UserName != "sa" || got.Password != "Passw0rd!" {
		t.Errorf("credentials = %q / %q", got.UserName, got.Password)
	}
	if _, found, _ := got.FedAuthToken(); found {
		t.Error("the FEDAUTH feature survived")
	}
	if len(got.Features) != 1 || got.Features[0].ID != 0x04 {
		t.Errorf("other features = %+v", got.Features)
	}
	if bytes.Contains(rebuilt.Marshal(), encodeUCS2("secret-token")) {
		t.Error("the access token is present in the upstream login")
	}

	// Without any other feature the extension flag is cleared.
	plain, _ := ParseLogin7(driverStyleLogin("orders", "app", "", "", "tok", false))
	m := plain.WithSQLAuth("sa", "x").Marshal()
	if m[27]&optionFlags3Extension != 0 {
		t.Error("extension flag still set")
	}
	// The original is untouched.
	if _, found, _ := orig.FedAuthToken(); !found {
		t.Error("WithSQLAuth modified the original")
	}
}

func TestPasswordObfuscation(t *testing.T) {
	t.Parallel()

	// "a" is 0x61 0x00 in UTF-16LE; nibble swap gives 0x16 0x00; XOR 0xA5 gives 0xB3 0xA5.
	if got := obfuscate(encodeUCS2("a")); !bytes.Equal(got, []byte{0xB3, 0xA5}) {
		t.Errorf("obfuscate = % X", got)
	}
	for _, s := range []string{"", "sa", "Passw0rd!", "näive", "😀"} {
		if got := decodeUCS2(deobfuscate(obfuscate(encodeUCS2(s)))); got != s {
			t.Errorf("round trip of %q = %q", s, got)
		}
	}
}

func TestLoginFailureNeverContainsToken(t *testing.T) {
	t.Parallel()

	const token = "super-secret-access-token"
	msg := loginFailure(18456, "Login failed for user '<token-identified principal>'.")
	if bytes.Contains(msg, []byte(token)) || bytes.Contains(msg, encodeUCS2(token)) {
		t.Error("the failure response contains the token")
	}
	if msg[0] != 0xAA {
		t.Errorf("first token = %#x, want ERROR", msg[0])
	}
	length := int(binary.LittleEndian.Uint16(msg[1:]))
	if got := binary.LittleEndian.Uint32(msg[3:]); got != 18456 {
		t.Errorf("error number = %d", got)
	}
	done := msg[3+length:]
	if done[0] != 0xFD || done[1]&0x02 == 0 || len(done) != 13 {
		t.Errorf("DONE token = % X", done)
	}
}

// TestHandshakeInsideTDS runs a TLS handshake wrapped in TDS packets between the two
// adapters and then exchanges data over raw TLS records.
func TestHandshakeInsideTDS(t *testing.T) {
	t.Parallel()

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_ = a.SetDeadline(time.Now().Add(10 * time.Second))
	_ = b.SetDeadline(time.Now().Add(10 * time.Second))

	cert := selfSigned(t)
	errc := make(chan error, 1)
	go func() {
		hc := &handshakeConn{Conn: b, writeType: typeReply}
		srv := tls.Server(hc, &tls.Config{Certificates: []tls.Certificate{cert}, MaxVersion: tls.VersionTLS12})
		if err := srv.Handshake(); err != nil {
			errc <- err
			return
		}
		if err := hc.finish(); err != nil {
			errc <- err
			return
		}
		buf := make([]byte, 5)
		if _, err := srv.Read(buf); err != nil {
			errc <- err
			return
		}
		_, err := srv.Write(bytes.ToUpper(buf))
		errc <- err
	}()

	hc := &handshakeConn{Conn: a, writeType: typePrelogin}
	cli := tls.Client(hc, &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12}) //nolint:gosec // test certificate
	if err := cli.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := hc.finish(); err != nil {
		t.Fatal(err)
	}
	if _, err := cli.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 5)
	if _, err := cli.Read(reply); err != nil || string(reply) != "HELLO" {
		t.Errorf("reply = %q, %v", reply, err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}
