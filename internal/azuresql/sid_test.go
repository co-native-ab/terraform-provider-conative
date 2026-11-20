package azuresql

import (
	"bytes"
	"testing"
)

const vectorID = "00112233-4455-6677-8899-aabbccddeeff"

func TestSIDFromEntraID(t *testing.T) {
	t.Parallel()

	want := []byte{0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	got, err := SIDFromEntraID(vectorID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("SIDFromEntraID = % X, want % X", got, want)
	}

	lit, err := SIDLiteral(vectorID)
	if err != nil {
		t.Fatal(err)
	}
	if lit != "0x33221100554477668899AABBCCDDEEFF" {
		t.Errorf("SIDLiteral = %s", lit)
	}

	upper, err := SIDLiteral("00112233-4455-6677-8899-AABBCCDDEEFF")
	if err != nil || upper != lit {
		t.Errorf("upper-case GUID gives %q, %v; want %q", upper, err, lit)
	}
}

func TestParseEntraID(t *testing.T) {
	t.Parallel()

	got, err := ParseEntraID("00112233-4455-6677-8899-AABBCCDDEEFF")
	if err != nil || got != vectorID {
		t.Errorf("ParseEntraID = %q, %v; want %q", got, err, vectorID)
	}

	invalid := []string{
		"",
		"{00112233-4455-6677-8899-aabbccddeeff}",
		"001122334455667788 99aabbccddeeff",
		"00112233445566778899aabbccddeeff",
		"00112233-4455-6677-8899-aabbccddeef",
		"00112233-4455-6677-8899-aabbccddeeff0",
		"00112233-4455-6677-8899-aabbccddeefg",
		"00112233_4455-6677-8899-aabbccddeeff",
		"0x0112233-4455-6677-8899-aabbccddeeff",
	}
	for _, s := range invalid {
		if _, err := ParseEntraID(s); err == nil {
			t.Errorf("ParseEntraID(%q) = nil error, want error", s)
		}
		if _, err := SIDFromEntraID(s); err == nil {
			t.Errorf("SIDFromEntraID(%q) = nil error, want error", s)
		}
		if _, err := SIDLiteral(s); err == nil {
			t.Errorf("SIDLiteral(%q) = nil error, want error", s)
		}
	}
}

func TestEntraIDFromSID(t *testing.T) {
	t.Parallel()

	sid, _ := SIDFromEntraID(vectorID)
	got, ok := EntraIDFromSID(sid)
	if !ok || got != vectorID {
		t.Errorf("EntraIDFromSID = %q, %v; want %q, true", got, ok, vectorID)
	}

	for _, n := range []int{0, 1, 15, 17, 28} {
		if id, ok := EntraIDFromSID(make([]byte, n)); ok {
			t.Errorf("EntraIDFromSID(%d bytes) = %q, true; want false", n, id)
		}
	}
}

func TestSIDHex(t *testing.T) {
	t.Parallel()

	if got := SIDHex([]byte{0x01, 0xab, 0xff}); got != "0x01ABFF" {
		t.Errorf("SIDHex = %q", got)
	}
	if got := SIDHex(nil); got != "0x" {
		t.Errorf("SIDHex(nil) = %q", got)
	}
}
