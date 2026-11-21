package dnscheck_test

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/co-native-ab/terraform-provider-conative/internal/acme/dnscheck"
)

// responder is a loopback UDP DNS server that answers NS and TXT queries. The TXT answer
// appears only after a number of polls.
type responder struct {
	conn     net.PacketConn
	txt      string
	appearAt int32
	polls    atomic.Int32

	mu    sync.Mutex
	names []string // names asked for, as received
}

func startResponder(t *testing.T, txt string, appearAt int32) *responder {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &responder{conn: conn, txt: txt, appearAt: appearAt}
	t.Cleanup(func() { _ = conn.Close() })
	go r.serve()
	return r
}

func (r *responder) serve() {
	buf := make([]byte, 512)
	for {
		n, addr, err := r.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		var q dnsmessage.Message
		if q.Unpack(buf[:n]) != nil || len(q.Questions) != 1 {
			continue
		}
		question := q.Questions[0]
		r.mu.Lock()
		r.names = append(r.names, question.Name.String())
		r.mu.Unlock()
		resp := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: q.ID, Response: true, Authoritative: true, RCode: dnsmessage.RCodeSuccess},
			Questions: q.Questions,
		}
		hdr := dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: 1}
		switch question.Type {
		case dnsmessage.TypeNS:
			hdr.Type = dnsmessage.TypeNS
			resp.Answers = append(resp.Answers, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.NSResource{NS: dnsmessage.MustNewName("ns1.example.org.")}})
		case dnsmessage.TypeTXT:
			hdr.Type = dnsmessage.TypeTXT
			if r.polls.Add(1) >= r.appearAt && r.txt != "" {
				resp.Answers = append(resp.Answers, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.TXTResource{TXT: []string{r.txt}}})
			} else {
				resp.RCode = dnsmessage.RCodeNameError
			}
		}
		out, err := resp.Pack()
		if err == nil {
			_, _ = r.conn.WriteTo(out, addr)
		}
	}
}

func (r *responder) checker(timeout time.Duration) dnscheck.Authoritative {
	addr := r.conn.LocalAddr().String()
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	return dnscheck.Authoritative{
		Timeout: timeout, Interval: 20 * time.Millisecond,
		Resolver: &net.Resolver{PreferGo: true, Dial: dial},
		Dial:     dial,
	}
}

func TestValuePresentReturnsAtOnce(t *testing.T) {
	r := startResponder(t, "value-1", 0)
	if err := r.checker(5*time.Second).Wait(context.Background(), "_acme-challenge.example.com", "example.com", []string{"value-1"}); err != nil {
		t.Fatal(err)
	}
}

func TestValueAppearingAfterTwoPolls(t *testing.T) {
	r := startResponder(t, "value-1", 3)
	if err := r.checker(5*time.Second).Wait(context.Background(), "_acme-challenge.example.com", "example.com", []string{"value-1"}); err != nil {
		t.Fatal(err)
	}
	if n := r.polls.Load(); n < 3 {
		t.Errorf("returned after %d polls", n)
	}
}

func TestNeverPresentNamesServerAndValue(t *testing.T) {
	r := startResponder(t, "", 0)
	err := r.checker(300*time.Millisecond).Wait(context.Background(), "_acme-challenge.example.com", "example.com", []string{"value-1"})
	if err == nil || !strings.Contains(err.Error(), "ns1.example.org") || !strings.Contains(err.Error(), "value-1") {
		t.Fatalf("want an error naming server and value, got %v", err)
	}
}

func TestCancellationStopsPolling(t *testing.T) {
	r := startResponder(t, "", 0)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(100 * time.Millisecond); cancel() }()
	start := time.Now()
	err := r.checker(time.Minute).Wait(ctx, "_acme-challenge.example.com", "example.com", []string{"v"})
	if err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("polling did not stop on cancellation: %v after %s", err, time.Since(start))
	}
}

// Names are queried as absolute names, so that a search list in the resolver
// configuration cannot make the check look at the wrong record.
func TestQueriesAreAbsolute(t *testing.T) {
	r := startResponder(t, "value-1", 0)
	if err := r.checker(5*time.Second).Wait(context.Background(), "_acme-challenge.example.com", "example.com", []string{"value-1"}); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.names) == 0 {
		t.Fatal("no query was seen")
	}
	for _, n := range r.names {
		if n != "example.com." && n != "_acme-challenge.example.com." {
			t.Errorf("unexpected query for %q", n)
		}
	}
}
