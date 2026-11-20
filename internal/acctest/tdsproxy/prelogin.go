package tdsproxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
)

// PRELOGIN option tokens (MS-TDS 2.2.6.5).
const (
	plVersion        byte = 0x00
	plEncryption     byte = 0x01
	plInstOpt        byte = 0x02
	plThreadID       byte = 0x03
	plMARS           byte = 0x04
	plTraceID        byte = 0x05
	plFedAuthRequire byte = 0x06
	plTerminator     byte = 0xFF
)

// ENCRYPTION option values.
const (
	encryptOff    byte = 0x00
	encryptOn     byte = 0x01
	encryptNotSup byte = 0x02
	encryptReq    byte = 0x03
)

// parsePrelogin reads the option table of a PRELOGIN message. The result maps each
// option token to its data.
func parsePrelogin(payload []byte) (map[byte][]byte, error) {
	opts := map[byte][]byte{}
	for pos := 0; ; pos += 5 {
		if pos >= len(payload) {
			return nil, errors.New("PRELOGIN option table is not terminated")
		}
		token := payload[pos]
		if token == plTerminator {
			return opts, nil
		}
		if pos+5 > len(payload) {
			return nil, errors.New("truncated PRELOGIN option")
		}
		offset := int(binary.BigEndian.Uint16(payload[pos+1:]))
		length := int(binary.BigEndian.Uint16(payload[pos+3:]))
		if offset+length > len(payload) {
			return nil, errors.New("PRELOGIN option data is out of range")
		}
		opts[token] = payload[offset : offset+length]
	}
}

type preloginOption struct {
	token byte
	data  []byte
}

// buildPrelogin writes an option table followed by the option data.
func buildPrelogin(opts []preloginOption) []byte {
	table := 5*len(opts) + 1
	var head, body bytes.Buffer
	for _, o := range opts {
		head.WriteByte(o.token)
		var b [4]byte
		binary.BigEndian.PutUint16(b[0:], uint16(table+body.Len())) //nolint:gosec // tiny tables
		binary.BigEndian.PutUint16(b[2:], uint16(len(o.data)))      //nolint:gosec // tiny tables
		head.Write(b[:])
		body.Write(o.data)
	}
	head.WriteByte(plTerminator)
	return append(head.Bytes(), body.Bytes()...)
}

// serverPrelogin answers a client PRELOGIN: it reports the given encryption mode,
// and echoes FEDAUTHREQUIRED when the client asked for federated authentication.
func serverPrelogin(client map[byte][]byte, encrypt byte) []byte {
	opts := []preloginOption{
		{plVersion, []byte{0x10, 0x00, 0x10, 0x00, 0x00, 0x00}},
		{plEncryption, []byte{encrypt}},
		{plInstOpt, []byte{0x00}},
		{plMARS, []byte{0x00}},
	}
	if v, ok := client[plFedAuthRequire]; ok && len(v) == 1 {
		opts = append(opts, preloginOption{plFedAuthRequire, []byte{1}})
	}
	return buildPrelogin(opts)
}

// handshakeConn carries a TLS handshake inside TDS packets, as the protocol requires
// when encryption is negotiated through PRELOGIN: what TLS writes between two reads
// is sent as one message of writeType, and what it reads comes out of the payload of
// incoming PRELOGIN or reply packets. After the handshake, pass is set and the
// connection becomes a plain pass-through, so TLS records travel directly.
type handshakeConn struct {
	net.Conn
	writeType byte
	pass      bool
	rbuf      []byte
	wbuf      bytes.Buffer
}

func (c *handshakeConn) Read(b []byte) (int, error) {
	if c.pass {
		return c.Conn.Read(b)
	}
	if err := c.flush(); err != nil {
		return 0, err
	}
	for len(c.rbuf) == 0 {
		typ, _, payload, err := readPacket(c.Conn)
		if err != nil {
			return 0, err
		}
		if typ != typePrelogin && typ != typeReply {
			return 0, errors.New("unexpected packet type during the TLS handshake")
		}
		c.rbuf = payload
	}
	n := copy(b, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

func (c *handshakeConn) Write(b []byte) (int, error) {
	if c.pass {
		return c.Conn.Write(b)
	}
	return c.wbuf.Write(b)
}

// flush sends what TLS has written so far as one message.
func (c *handshakeConn) flush() error {
	if c.wbuf.Len() == 0 {
		return nil
	}
	err := writeMessage(c.Conn, c.writeType, c.wbuf.Bytes(), 4096)
	c.wbuf.Reset()
	return err
}

// finish flushes the last handshake flight and switches to pass-through.
func (c *handshakeConn) finish() error {
	if err := c.flush(); err != nil {
		return err
	}
	c.pass = true
	return nil
}
