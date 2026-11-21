package acme

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"
)

func TestNeedsOrder(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	boundary := now.Add(30 * 24 * time.Hour)
	if ok, why := NeedsOrder(now, boundary, 30, "v1", "v1", false); !ok || why == "" {
		t.Errorf("exactly at the boundary must order: %v %q", ok, why)
	}
	if ok, _ := NeedsOrder(now, boundary.Add(time.Second), 30, "v1", "v1", false); ok {
		t.Error("one second outside the window must not order")
	}
	if ok, why := NeedsOrder(now, boundary.Add(time.Hour*24*365), 30, "v2", "v1", false); !ok || why == "" {
		t.Errorf("external version: %v %q", ok, why)
	}
	if ok, _ := NeedsOrder(now, boundary.Add(time.Hour*24*365), 30, "v1", "v1", true); !ok {
		t.Error("changed names must order")
	}
	if !InsideWindow(now, boundary, 30) || InsideWindow(now, boundary.Add(time.Second), 30) {
		t.Error("InsideWindow")
	}
}

func TestNamesChanged(t *testing.T) {
	t.Parallel()
	if NamesChanged("a.example.com", []string{"b.example.com", "c.example.com", "b.example.com"}, "a.example.com", []string{"c.example.com", "b.example.com"}) {
		t.Error("order and duplicates must not matter")
	}
	if NamesChanged("a.example.com", nil, "a.example.com", []string{}) {
		t.Error("null equals empty")
	}
	if !NamesChanged("a.example.com", nil, "b.example.com", nil) || !NamesChanged("a.example.com", []string{"x.example.com"}, "a.example.com", nil) {
		t.Error("a difference must be reported")
	}
	if KeyTypeChanged("RSA2048", "RSA2048") || !KeyTypeChanged("RSA2048", "RSA 1024") {
		t.Error("KeyTypeChanged")
	}
}

func TestECDSASignatureConversion(t *testing.T) {
	t.Parallel()
	for size, curve := range map[int]elliptic.Curve{32: elliptic.P256(), 48: elliptic.P384(), 66: elliptic.P521()} {
		key, _ := ecdsa.GenerateKey(curve, rand.Reader)
		for i := 0; i < 20; i++ {
			der, err := ecdsa.SignASN1(rand.Reader, key, []byte("digest-digest-digest-digest-1234"))
			if err != nil {
				t.Fatal(err)
			}
			raw, err := ASN1ToRaw(der, size)
			if err != nil || len(raw) != 2*size {
				t.Fatalf("%v %d", err, len(raw))
			}
			back, err := RawToASN1(raw, size)
			if err != nil || !bytes.Equal(back, der) {
				t.Fatalf("round trip: %v", err)
			}
		}
	}
	// Leading zero bytes and high-bit values survive.
	raw := append(append([]byte{0, 0, 1}, make([]byte, 29)...), append([]byte{0xff}, make([]byte, 31)...)...)
	der, err := RawToASN1(raw, 32)
	if err != nil {
		t.Fatal(err)
	}
	if back, err := ASN1ToRaw(der, 32); err != nil || !bytes.Equal(back, raw) {
		t.Errorf("padding: %v", err)
	}
	if _, err := RawToASN1(make([]byte, 63), 32); err == nil {
		t.Error("wrong length accepted")
	}
	if _, err := ASN1ToRaw(append(der, 0), 32); err == nil {
		t.Error("trailing data accepted")
	}
}
