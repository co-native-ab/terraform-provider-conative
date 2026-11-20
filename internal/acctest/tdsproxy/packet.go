package tdsproxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// TDS packet types used by the proxy.
const (
	typeReply      byte = 0x04
	typeLogin7     byte = 0x10
	typePrelogin   byte = 0x12
	statusEOM      byte = 0x01
	headerLen           = 8
	maxMessageSize      = 1 << 20
)

// readPacket reads one TDS packet and returns its type, status and payload.
func readPacket(r io.Reader) (typ, status byte, payload []byte, err error) {
	var hdr [headerLen]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return 0, 0, nil, err
	}
	length := int(binary.BigEndian.Uint16(hdr[2:4]))
	if length < headerLen {
		return 0, 0, nil, fmt.Errorf("invalid TDS packet length %d", length)
	}
	payload = make([]byte, length-headerLen)
	if _, err = io.ReadFull(r, payload); err != nil {
		return 0, 0, nil, err
	}
	return hdr[0], hdr[1], payload, nil
}

// readMessage reads packets until one has the end-of-message bit and returns the
// concatenated payload. All packets of a message must have the same type.
func readMessage(r io.Reader) (typ byte, payload []byte, err error) {
	for first := true; ; first = false {
		t, status, p, err := readPacket(r)
		if err != nil {
			return 0, nil, err
		}
		if first {
			typ = t
		} else if t != typ {
			return 0, nil, errors.New("TDS message mixes packet types")
		}
		payload = append(payload, p...)
		if len(payload) > maxMessageSize {
			return 0, nil, errors.New("TDS message too large")
		}
		if status&statusEOM != 0 {
			return typ, payload, nil
		}
	}
}

// writeMessage writes payload as one message of the given type, split into packets of
// at most packetSize bytes (header included).
func writeMessage(w io.Writer, typ byte, payload []byte, packetSize int) error {
	if packetSize <= headerLen || packetSize > 65535 {
		packetSize = 4096
	}
	chunk := packetSize - headerLen
	for id := byte(1); ; id++ {
		n := min(len(payload), chunk)
		status := byte(0)
		if n == len(payload) {
			status = statusEOM
		}
		pkt := make([]byte, headerLen+n)
		pkt[0], pkt[1] = typ, status
		binary.BigEndian.PutUint16(pkt[2:4], uint16(headerLen+n)) //nolint:gosec // bounded by packetSize
		pkt[6] = id
		copy(pkt[headerLen:], payload[:n])
		if _, err := w.Write(pkt); err != nil {
			return err
		}
		payload = payload[n:]
		if status == statusEOM {
			return nil
		}
	}
}
