package tdsproxy_test

import (
	"net"
	"strconv"
	"testing"
)

func mustPort(t *testing.T, addr string) uint64 {
	t.Helper()
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.ParseUint(p, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
