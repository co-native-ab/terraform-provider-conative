package tdsproxy

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf16"
)

const (
	login7HeaderLen = 94

	featureFedAuth byte = 0x02
	featureTerm    byte = 0xFF

	optionFlags3Extension byte = 0x10

	fedAuthLibrarySecurityToken = 0x01
)

// Feature is one entry of the LOGIN7 feature extension block.
type Feature struct {
	ID   byte
	Data []byte
}

// Login7 is the parsed form of a LOGIN7 message (MS-TDS 2.2.6.4). Strings are held
// decoded; Password and ChangePassword are held de-obfuscated.
type Login7 struct {
	TDSVersion     uint32
	PacketSize     uint32
	ClientProgVer  uint32
	ClientPID      uint32
	ConnectionID   uint32
	OptionFlags1   byte
	OptionFlags2   byte
	TypeFlags      byte
	OptionFlags3   byte
	ClientTimeZone int32
	ClientLCID     uint32
	HostName       string
	UserName       string
	Password       string
	AppName        string
	ServerName     string
	CtlIntName     string
	Language       string
	Database       string
	ClientID       [6]byte
	SSPI           []byte
	AtchDBFile     string
	ChangePassword string
	Features       []Feature
}

// ParseLogin7 parses a LOGIN7 message and walks its feature extension block.
func ParseLogin7(p []byte) (*Login7, error) {
	if len(p) < login7HeaderLen {
		return nil, errors.New("LOGIN7 message is shorter than its fixed header")
	}
	le := binary.LittleEndian
	if int(le.Uint32(p[0:])) > len(p) {
		return nil, errors.New("LOGIN7 length field exceeds the message")
	}
	l := &Login7{
		TDSVersion:     le.Uint32(p[4:]),
		PacketSize:     le.Uint32(p[8:]),
		ClientProgVer:  le.Uint32(p[12:]),
		ClientPID:      le.Uint32(p[16:]),
		ConnectionID:   le.Uint32(p[20:]),
		OptionFlags1:   p[24],
		OptionFlags2:   p[25],
		TypeFlags:      p[26],
		OptionFlags3:   p[27],
		ClientTimeZone: int32(le.Uint32(p[28:])), //nolint:gosec // reinterpretation of a signed field
		ClientLCID:     le.Uint32(p[32:]),
	}
	copy(l.ClientID[:], p[72:78])

	str := func(field int) (string, error) {
		off, n := int(le.Uint16(p[field:])), int(le.Uint16(p[field+2:]))
		return ucs2(p, off, n)
	}
	var err error
	for _, f := range []struct {
		dst   *string
		field int
	}{
		{&l.HostName, 36}, {&l.UserName, 40}, {&l.AppName, 48}, {&l.ServerName, 52},
		{&l.CtlIntName, 60}, {&l.Language, 64}, {&l.Database, 68}, {&l.AtchDBFile, 82},
	} {
		if *f.dst, err = str(f.field); err != nil {
			return nil, err
		}
	}
	secret := func(field int) (string, error) {
		off, n := int(le.Uint16(p[field:])), int(le.Uint16(p[field+2:]))
		if n == 0 {
			return "", nil
		}
		if off < login7HeaderLen || off+2*n > len(p) {
			return "", errors.New("LOGIN7 string is out of range")
		}
		return decodeUCS2(deobfuscate(p[off : off+2*n])), nil
	}
	if l.Password, err = secret(44); err != nil {
		return nil, err
	}
	if l.ChangePassword, err = secret(86); err != nil {
		return nil, err
	}

	sspiOff, sspiLen := int(le.Uint16(p[78:])), int(le.Uint16(p[80:]))
	if sspiLen > 0 {
		if sspiOff+sspiLen > len(p) {
			return nil, errors.New("LOGIN7 SSPI data is out of range")
		}
		l.SSPI = append([]byte(nil), p[sspiOff:sspiOff+sspiLen]...)
	}

	if l.OptionFlags3&optionFlags3Extension != 0 {
		extOff, extLen := int(le.Uint16(p[56:])), int(le.Uint16(p[58:]))
		if extLen < 4 || extOff+4 > len(p) {
			return nil, errors.New("LOGIN7 feature extension pointer is out of range")
		}
		if l.Features, err = parseFeatures(p, int(le.Uint32(p[extOff:]))); err != nil {
			return nil, err
		}
	}
	return l, nil
}

// ucs2 decodes n UTF-16LE code units at offset off.
func ucs2(p []byte, off, n int) (string, error) {
	if n == 0 {
		return "", nil
	}
	if off < login7HeaderLen || off+2*n > len(p) {
		return "", errors.New("LOGIN7 string is out of range")
	}
	return decodeUCS2(p[off : off+2*n]), nil
}

func parseFeatures(p []byte, pos int) ([]Feature, error) {
	var out []Feature
	for {
		if pos >= len(p) {
			return nil, errors.New("LOGIN7 feature extension is not terminated")
		}
		id := p[pos]
		if id == featureTerm {
			return out, nil
		}
		if pos+5 > len(p) {
			return nil, errors.New("truncated LOGIN7 feature header")
		}
		n := int(binary.LittleEndian.Uint32(p[pos+1:]))
		if n < 0 || pos+5+n > len(p) {
			return nil, errors.New("LOGIN7 feature data is out of range")
		}
		out = append(out, Feature{ID: id, Data: append([]byte(nil), p[pos+5:pos+5+n]...)})
		pos += 5 + n
	}
}

// obfuscate and deobfuscate implement the LOGIN7 password transformation: swap the
// nibbles of every byte and XOR with 0xA5.
func obfuscate(utf16le []byte) []byte {
	out := make([]byte, len(utf16le))
	for i, b := range utf16le {
		out[i] = (b<<4 | b>>4) ^ 0xA5
	}
	return out
}

func deobfuscate(obfuscated []byte) []byte {
	out := make([]byte, len(obfuscated))
	for i, b := range obfuscated {
		b ^= 0xA5
		out[i] = b<<4 | b>>4
	}
	return out
}

func decodeUCS2(b []byte) string {
	units := make([]uint16, len(b)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(units))
}

func encodeUCS2(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(out[2*i:], u)
	}
	return out
}

// Marshal writes the LOGIN7 message in the layout clients use: the fixed header, the
// variable-length fields in header order, the SSPI blob, then (when there are
// features) a DWORD pointing at the feature block, and the block itself. The feature
// extension flag is derived from the features present.
func (l *Login7) Marshal() []byte {
	type field struct {
		data  []byte
		chars int
	}
	str := func(s string) field { return field{encodeUCS2(s), len(utf16.Encode([]rune(s)))} }
	secret := func(s string) field {
		e := encodeUCS2(s)
		return field{obfuscate(e), len(e) / 2}
	}
	// Order: host, user, password, app, server, ctl, language, database, atch, change.
	f := []field{
		str(l.HostName), str(l.UserName), secret(l.Password), str(l.AppName), str(l.ServerName),
		str(l.CtlIntName), str(l.Language), str(l.Database), str(l.AtchDBFile), secret(l.ChangePassword),
	}
	const (
		host, user, pass, app, server, ctl, lang, db, atch, change = 0, 1, 2, 3, 4, 5, 6, 7, 8, 9
	)

	var body bytes.Buffer
	offsets := make([]int, len(f))
	pos := login7HeaderLen
	add := func(i int) {
		offsets[i] = pos
		body.Write(f[i].data)
		pos += len(f[i].data)
	}
	for _, i := range []int{host, user, pass, app, server, ctl, lang, db} {
		add(i)
	}
	sspiOff := pos
	body.Write(l.SSPI)
	pos += len(l.SSPI)
	add(atch)
	add(change)

	var feat []byte
	for _, ft := range l.Features {
		var h [5]byte
		h[0] = ft.ID
		binary.LittleEndian.PutUint32(h[1:], uint32(len(ft.Data))) //nolint:gosec // bounded by packet limits
		feat = append(append(feat, h[:]...), ft.Data...)
	}
	flags3 := l.OptionFlags3 &^ optionFlags3Extension
	extOff, extLen := 0, 0
	if len(feat) > 0 {
		flags3 |= optionFlags3Extension
		feat = append(feat, featureTerm)
		extOff, extLen = pos, 4
		var ptr [4]byte
		binary.LittleEndian.PutUint32(ptr[:], uint32(pos+4)) //nolint:gosec // bounded by packet limits
		body.Write(ptr[:])
		pos += 4
		body.Write(feat)
		pos += len(feat)
	}

	hdr := make([]byte, login7HeaderLen)
	le := binary.LittleEndian
	le.PutUint32(hdr[0:], uint32(login7HeaderLen+body.Len())) //nolint:gosec // bounded by packet limits
	le.PutUint32(hdr[4:], l.TDSVersion)
	le.PutUint32(hdr[8:], l.PacketSize)
	le.PutUint32(hdr[12:], l.ClientProgVer)
	le.PutUint32(hdr[16:], l.ClientPID)
	le.PutUint32(hdr[20:], l.ConnectionID)
	hdr[24], hdr[25], hdr[26], hdr[27] = l.OptionFlags1, l.OptionFlags2, l.TypeFlags, flags3
	le.PutUint32(hdr[28:], uint32(l.ClientTimeZone)) //nolint:gosec // reinterpretation of a signed field
	le.PutUint32(hdr[32:], l.ClientLCID)
	put := func(at, off, n int) {
		le.PutUint16(hdr[at:], uint16(off)) //nolint:gosec // LOGIN7 offsets and lengths are 16-bit by definition
		le.PutUint16(hdr[at+2:], uint16(n)) //nolint:gosec // LOGIN7 offsets and lengths are 16-bit by definition
	}
	put(36, offsets[host], f[host].chars)
	put(40, offsets[user], f[user].chars)
	put(44, offsets[pass], f[pass].chars)
	put(48, offsets[app], f[app].chars)
	put(52, offsets[server], f[server].chars)
	put(56, extOff, extLen)
	put(60, offsets[ctl], f[ctl].chars)
	put(64, offsets[lang], f[lang].chars)
	put(68, offsets[db], f[db].chars)
	copy(hdr[72:78], l.ClientID[:])
	put(78, sspiOff, len(l.SSPI))
	put(82, offsets[atch], f[atch].chars)
	put(86, offsets[change], f[change].chars)
	return append(hdr, body.Bytes()...)
}

// FedAuthToken extracts the federated authentication feature: the access token as
// UTF-16LE bytes, as carried in the message. found is false when there is no FEDAUTH
// feature; an error means the feature is malformed or uses another library.
func (l *Login7) FedAuthToken() (token []byte, found bool, err error) {
	for _, f := range l.Features {
		if f.ID != featureFedAuth {
			continue
		}
		if len(f.Data) < 5 {
			return nil, true, errors.New("FEDAUTH feature is truncated")
		}
		if lib := f.Data[0] >> 1; lib != fedAuthLibrarySecurityToken {
			return nil, true, fmt.Errorf("FEDAUTH library %#x is not supported", lib)
		}
		n := int(binary.LittleEndian.Uint32(f.Data[1:]))
		if n < 0 || 5+n > len(f.Data) {
			return nil, true, errors.New("FEDAUTH token is out of range")
		}
		return f.Data[5 : 5+n], true, nil
	}
	return nil, false, nil
}

// TokenMatches compares a token carried in a LOGIN7 message with the expected token in
// constant time.
func TokenMatches(carried []byte, expected string) bool {
	return subtle.ConstantTimeCompare(carried, encodeUCS2(expected)) == 1
}

// WithSQLAuth returns a copy of the login that signs in with SQL authentication
// instead: the FEDAUTH feature is dropped, every other field is kept.
func (l *Login7) WithSQLAuth(user, password string) *Login7 {
	c := *l
	c.UserName, c.Password = user, password
	c.SSPI = nil
	c.Features = nil
	for _, f := range l.Features {
		if f.ID != featureFedAuth {
			c.Features = append(c.Features, f)
		}
	}
	return &c
}

// loginFailure builds the response to a refused login: an ERROR token with the given
// number and message followed by a DONE token with the error bit set.
func loginFailure(number int32, message string) []byte {
	le := binary.LittleEndian
	msg := encodeUCS2(message)
	const serverName = "tdsproxy"
	server := encodeUCS2(serverName)

	var body bytes.Buffer
	var n [4]byte
	le.PutUint32(n[:], uint32(number)) //nolint:gosec // reinterpretation of a signed field
	body.Write(n[:])
	body.WriteByte(1)  // state
	body.WriteByte(14) // class
	var u16 [2]byte
	le.PutUint16(u16[:], uint16(len(msg)/2)) //nolint:gosec // short messages
	body.Write(u16[:])
	body.Write(msg)
	body.WriteByte(byte(len(serverName)))
	body.Write(server)
	body.WriteByte(0)              // procedure name
	body.Write([]byte{1, 0, 0, 0}) // line number

	var out bytes.Buffer
	out.WriteByte(0xAA)
	le.PutUint16(u16[:], uint16(body.Len())) //nolint:gosec // short messages
	out.Write(u16[:])
	out.Write(body.Bytes())

	out.WriteByte(0xFD)                       // DONE
	out.Write([]byte{0x02, 0x00})             // status: error
	out.Write([]byte{0x00, 0x00})             // current command
	out.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0}) // row count
	return out.Bytes()
}
