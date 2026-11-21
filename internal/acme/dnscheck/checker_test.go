package dnscheck_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/co-native-ab/terraform-provider-conative/internal/acme/dnscheck"
)

// responder is a loopback DNS server (UDP and TCP) that answers NS, A and TXT queries.
// The TXT answer appears only after a number of polls.
type responder struct {
	conn     net.PacketConn
	listener net.Listener
	txt      string
	appearAt int32
	polls    atomic.Int32

	mu            sync.Mutex
	names         []string  // names asked for, as received
	txtRD         []bool    // RecursionDesired of every TXT query
	firstTXT      time.Time // when the first TXT query arrived
	nonAuth       bool      // answer without the authoritative-answer flag
	truncateUDP   bool      // answer TXT queries over UDP with TC set and no answer
	tcpQueries    int
	nonAuthPolls  int32 // number of TXT polls answered without the flag before it is set
	nonAuthServed int32
	// failRCode, when not zero, is the rcode of every TXT answer; failAA says whether
	// those answers carry the authoritative-answer flag.
	failRCode dnsmessage.RCode
	failAA    bool
	// nsCount is the number of name servers the NS answer lists (one when zero): ns1,
	// ns2, ... under example.org, at 127.0.0.1, 127.0.0.2, ...
	nsCount int
}

func startResponder(t *testing.T, txt string, appearAt int32) *responder {
	t.Helper()
	// UDP and TCP share a port number; another process may hold the TCP side of the one
	// the system picked, so try again with another.
	var conn net.PacketConn
	var ln net.Listener
	for attempt := 0; ; attempt++ {
		var err error
		if conn, err = net.ListenPacket("udp", "127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		if ln, err = net.Listen("tcp", conn.LocalAddr().String()); err == nil {
			break
		}
		_ = conn.Close()
		if attempt == 50 {
			t.Fatal(err)
		}
	}
	r := &responder{conn: conn, listener: ln, txt: txt, appearAt: appearAt}
	t.Cleanup(func() { _ = conn.Close(); _ = ln.Close() })
	go r.serveUDP()
	go r.serveTCP()
	return r
}

func (r *responder) serveUDP() {
	buf := make([]byte, 512)
	for {
		n, addr, err := r.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		if out := r.answer(buf[:n], false); out != nil {
			_, _ = r.conn.WriteTo(out, addr)
		}
	}
}

func (r *responder) serveTCP() {
	for {
		c, err := r.listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = c.Close() }()
			var lb [2]byte
			if _, err := io.ReadFull(c, lb[:]); err != nil {
				return
			}
			buf := make([]byte, binary.BigEndian.Uint16(lb[:]))
			if _, err := io.ReadFull(c, buf); err != nil {
				return
			}
			out := r.answer(buf, true)
			if out == nil {
				return
			}
			_, _ = c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(out))), out...))
		}()
	}
}

func (r *responder) answer(in []byte, tcp bool) []byte {
	var q dnsmessage.Message
	if q.Unpack(in) != nil || len(q.Questions) != 1 {
		return nil
	}
	question := q.Questions[0]
	r.mu.Lock()
	defer r.mu.Unlock()
	r.names = append(r.names, question.Name.String())
	resp := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: q.ID, Response: true, Authoritative: true, RCode: dnsmessage.RCodeSuccess},
		Questions: q.Questions,
	}
	hdr := dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: 1}
	switch question.Type {
	case dnsmessage.TypeNS:
		hdr.Type = dnsmessage.TypeNS
		for i := 1; i <= max(r.nsCount, 1); i++ {
			ns := dnsmessage.MustNewName(fmt.Sprintf("ns%d.example.org.", i))
			resp.Answers = append(resp.Answers, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.NSResource{NS: ns}})
		}
	case dnsmessage.TypeA:
		hdr.Type = dnsmessage.TypeA
		last := byte(1)
		if n, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(question.Name.String(), "ns"), ".example.org.")); err == nil && n > 0 && n < 255 {
			last = byte(n)
		}
		resp.Answers = append(resp.Answers, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, last}}})
	case dnsmessage.TypeTXT:
		if r.firstTXT.IsZero() {
			r.firstTXT = time.Now()
		}
		r.txtRD = append(r.txtRD, q.RecursionDesired)
		if tcp {
			r.tcpQueries++
		}
		if r.nonAuth || r.nonAuthServed < r.nonAuthPolls {
			resp.Authoritative = false
			r.nonAuthServed++
		}
		if r.failRCode != 0 {
			resp.RCode = r.failRCode
			resp.Authoritative = r.failAA
			break
		}
		if r.truncateUDP && !tcp {
			resp.Truncated = true
			break
		}
		hdr.Type = dnsmessage.TypeTXT
		if r.polls.Add(1) >= r.appearAt && r.txt != "" {
			resp.Answers = append(resp.Answers, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.TXTResource{TXT: []string{r.txt}}})
		} else {
			resp.RCode = dnsmessage.RCodeNameError
		}
	}
	out, err := resp.Pack()
	if err != nil {
		return nil
	}
	return out
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

// checkerOf is a checker for a zone served by r, which names count name servers: ns1 is
// r itself and ns2, ns3, ... are the responders in others. Every query for a record goes
// to the responder of the name server's address.
func (r *responder) checkerOf(timeout time.Duration, others ...*responder) dnscheck.Authoritative {
	r.mu.Lock()
	r.nsCount = 1 + len(others)
	r.mu.Unlock()
	byIP := map[string]string{"127.0.0.1": r.conn.LocalAddr().String()}
	for i, o := range others {
		byIP[fmt.Sprintf("127.0.0.%d", i+2)] = o.conn.LocalAddr().String()
	}
	lookup := r.conn.LocalAddr().String()
	return dnscheck.Authoritative{
		Timeout: timeout, Interval: 20 * time.Millisecond,
		Resolver: &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, lookup)
		}},
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, _, _ := net.SplitHostPort(address)
			var d net.Dialer
			return d.DialContext(ctx, network, byIP[host])
		},
	}
}

func (r *responder) txtQueries() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.txtRD)
}

func (r *responder) answerWith(code dnsmessage.RCode, aa bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failRCode, r.failAA = code, aa
}

func rec(values ...string) []dnscheck.Record {
	return []dnscheck.Record{{FQDN: "_acme-challenge.example.com", Zone: "example.com", Values: values}}
}

func TestValuePresentReturnsAtOnce(t *testing.T) {
	r := startResponder(t, "value-1", 0)
	if err := r.checker(5*time.Second).Wait(context.Background(), rec("value-1")); err != nil {
		t.Fatal(err)
	}
}

func TestValueAppearingAfterTwoPolls(t *testing.T) {
	r := startResponder(t, "value-1", 3)
	if err := r.checker(5*time.Second).Wait(context.Background(), rec("value-1")); err != nil {
		t.Fatal(err)
	}
	if n := r.polls.Load(); n < 3 {
		t.Errorf("returned after %d polls", n)
	}
}

func TestNeverPresentNamesServerAndValue(t *testing.T) {
	r := startResponder(t, "", 0)
	err := r.checker(300*time.Millisecond).Wait(context.Background(), rec("value-1"))
	if err == nil || !strings.Contains(err.Error(), "ns1.example.org") || !strings.Contains(err.Error(), "value-1") {
		t.Fatalf("want an error naming server and value, got %v", err)
	}
	if strings.Contains(err.Error(), "authoritative-answer") {
		t.Errorf("an authoritative negative answer is not an interception: %v", err)
	}
}

func TestCancellationStopsPolling(t *testing.T) {
	r := startResponder(t, "", 0)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(100 * time.Millisecond); cancel() }()
	start := time.Now()
	err := r.checker(time.Minute).Wait(ctx, rec("v"))
	if err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("polling did not stop on cancellation: %v after %s", err, time.Since(start))
	}
}

// Names are queried as absolute names, so that a search list in the resolver
// configuration cannot make the check look at the wrong record.
func TestQueriesAreAbsolute(t *testing.T) {
	r := startResponder(t, "value-1", 0)
	if err := r.checker(5*time.Second).Wait(context.Background(), rec("value-1")); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.names) == 0 {
		t.Fatal("no query was seen")
	}
	for _, n := range r.names {
		if n != "example.com." && n != "_acme-challenge.example.com." && n != "ns1.example.org." {
			t.Errorf("unexpected query for %q", n)
		}
	}
}

// The name server must answer from its own data: the TXT queries do not ask for
// recursion.
func TestTXTQueriesDoNotRequestRecursion(t *testing.T) {
	r := startResponder(t, "value-1", 0)
	if err := r.checker(5*time.Second).Wait(context.Background(), rec("value-1")); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.txtRD) == 0 {
		t.Fatal("no TXT query was seen")
	}
	for _, rd := range r.txtRD {
		if rd {
			t.Error("a TXT query had the recursion-desired flag set")
		}
	}
}

// An answer without the authoritative-answer flag came from something that is not the
// zone's name server. It is never taken as proof, even when it holds the value.
func TestAnswerWithoutAuthoritativeFlagIsNotTrusted(t *testing.T) {
	r := startResponder(t, "value-1", 0)
	r.mu.Lock()
	r.nonAuth = true
	r.mu.Unlock()
	err := r.checker(300*time.Millisecond).Wait(context.Background(), rec("value-1"))
	if err == nil {
		t.Fatal("a non-authoritative answer was accepted")
	}
	for _, want := range []string{"authoritative-answer flag", "dns_propagation_check = false", "ns1.example.org"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// A non-authoritative answer is not a verdict either way: polling goes on and succeeds
// once the name server itself answers.
func TestPollingContinuesAfterNonAuthoritativeAnswer(t *testing.T) {
	r := startResponder(t, "value-1", 0)
	r.mu.Lock()
	r.nonAuthPolls = 3
	r.mu.Unlock()
	if err := r.checker(5*time.Second).Wait(context.Background(), rec("value-1")); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	n := len(r.txtRD)
	r.mu.Unlock()
	if n < 4 {
		t.Errorf("only %d queries; the non-authoritative answers should have been polled past", n)
	}
}

func TestTruncatedAnswerFallsBackToTCP(t *testing.T) {
	r := startResponder(t, "value-1", 0)
	r.mu.Lock()
	r.truncateUDP = true
	r.mu.Unlock()
	if err := r.checker(5*time.Second).Wait(context.Background(), rec("value-1")); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.tcpQueries == 0 {
		t.Error("no query went over TCP")
	}
	for _, rd := range r.txtRD {
		if rd {
			t.Error("the TCP query asked for recursion")
		}
	}
}

func TestWaitsBeforeTheFirstPoll(t *testing.T) {
	r := startResponder(t, "value-1", 0)
	c := r.checker(5 * time.Second)
	c.InitialDelay = 200 * time.Millisecond
	start := time.Now()
	if err := c.Wait(context.Background(), rec("value-1")); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if gap := r.firstTXT.Sub(start); gap < 200*time.Millisecond {
		t.Errorf("the first TXT query came %s after the start, want at least the initial delay", gap)
	}
}

func TestSeveralRecordsMustAllBeVisible(t *testing.T) {
	r := startResponder(t, "value-1", 0)
	records := []dnscheck.Record{
		{FQDN: "_acme-challenge.example.com", Zone: "example.com", Values: []string{"value-1"}},
		{FQDN: "_acme-challenge.www.example.com", Zone: "example.com", Values: []string{"value-1", "other"}},
	}
	err := r.checker(300*time.Millisecond).Wait(context.Background(), records)
	if err == nil || !strings.Contains(err.Error(), `"other"`) {
		t.Fatalf("want an error naming the value that is missing, got %v", err)
	}
}

func TestDelayOnlyWaitsOnceAndChecksNothing(t *testing.T) {
	d := dnscheck.DelayOnly{Delay: 150 * time.Millisecond}
	records := []dnscheck.Record{
		{FQDN: "a.example.com", Zone: "example.com", Values: []string{"x"}},
		{FQDN: "b.example.com", Zone: "example.com", Values: []string{"y"}},
	}
	start := time.Now()
	if err := d.Wait(context.Background(), records); err != nil {
		t.Fatal(err)
	}
	if got := time.Since(start); got < 150*time.Millisecond || got > 2*time.Second {
		t.Errorf("waited %s", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (dnscheck.DelayOnly{Delay: time.Minute}).Wait(ctx, records); err == nil {
		t.Error("a cancelled wait returned no error")
	}
}

// Every name server of a zone that answers SERVFAIL or REFUSED without the
// authoritative-answer flag is a DNS-intercepting proxy that does not pass the query on:
// the check fails in the first round, with the hint, instead of waiting for the timeout.
func TestEveryServerFailingWithoutFlagFailsAtOnce(t *testing.T) {
	for name, code := range map[string]dnsmessage.RCode{"SERVFAIL": dnsmessage.RCodeServerFailure, "REFUSED": dnsmessage.RCodeRefused} {
		t.Run(name, func(t *testing.T) {
			r1 := startResponder(t, "value-1", 0)
			r2 := startResponder(t, "value-1", 0)
			r1.answerWith(code, false)
			r2.answerWith(code, false)
			start := time.Now()
			err := r1.checkerOf(30*time.Second, r2).Wait(context.Background(), rec("value-1"))
			if err == nil {
				t.Fatal("no error")
			}
			if elapsed := time.Since(start); elapsed > 5*time.Second {
				t.Errorf("took %s; it should fail before the timeout", elapsed)
			}
			for _, want := range []string{name, "every name server", "example.com", "authoritative-answer flag", "DNS-intercepting proxy", "dns_propagation_check = false"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not mention %q", err, want)
				}
			}
			if strings.Contains(err.Error(), "waited") {
				t.Errorf("error %q is the timeout error", err)
			}
			// The first round asked every name server.
			if r1.txtQueries() != 1 || r2.txtQueries() != 1 {
				t.Errorf("queries: %d and %d, want one each", r1.txtQueries(), r2.txtQueries())
			}
		})
	}
}

// When one name server answers properly the check does not fail early; at the timeout
// the error still carries the hint.
func TestSomeServersFailingWithoutFlagDoesNotFailEarly(t *testing.T) {
	r1 := startResponder(t, "value-1", 0)
	r2 := startResponder(t, "value-1", 0)
	r2.answerWith(dnsmessage.RCodeServerFailure, false)
	start := time.Now()
	err := r1.checkerOf(600*time.Millisecond, r2).Wait(context.Background(), rec("value-1"))
	if err == nil {
		t.Fatal("no error")
	}
	if elapsed := time.Since(start); elapsed < 500*time.Millisecond {
		t.Errorf("failed after %s, before the timeout", elapsed)
	}
	for _, want := range []string{"SERVFAIL", "waited", "authoritative-answer flag", "DNS-intercepting proxy", "dns_propagation_check = false"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
	if r1.txtQueries() < 2 {
		t.Errorf("polling stopped after %d queries", r1.txtQueries())
	}
}

// An authoritative SERVFAIL is the name server's own failure, not a proxy: it is retried
// until the timeout and carries no proxy hint.
func TestAuthoritativeServfailIsRetriedUntilTimeout(t *testing.T) {
	r := startResponder(t, "value-1", 0)
	r.answerWith(dnsmessage.RCodeServerFailure, true)
	start := time.Now()
	err := r.checkerOf(400*time.Millisecond).Wait(context.Background(), rec("value-1"))
	if err == nil {
		t.Fatal("no error")
	}
	if elapsed := time.Since(start); elapsed < 300*time.Millisecond {
		t.Errorf("failed after %s, before the timeout", elapsed)
	}
	if !strings.Contains(err.Error(), "SERVFAIL") || !strings.Contains(err.Error(), "waited") {
		t.Errorf("error %q should be the timeout error naming SERVFAIL", err)
	}
	if strings.Contains(err.Error(), "dns_propagation_check") {
		t.Errorf("error %q has the proxy hint although the answer was authoritative", err)
	}
	if r.txtQueries() < 2 {
		t.Errorf("polling stopped after %d queries", r.txtQueries())
	}
}

// A zone with a single name server that answers SERVFAIL without the flag also fails at
// once.
func TestSingleServerFailingWithoutFlagFailsAtOnce(t *testing.T) {
	r := startResponder(t, "value-1", 0)
	r.answerWith(dnsmessage.RCodeRefused, false)
	start := time.Now()
	err := r.checker(30*time.Second).Wait(context.Background(), rec("value-1"))
	if err == nil || !strings.Contains(err.Error(), "dns_propagation_check = false") {
		t.Fatalf("error: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("took %s", elapsed)
	}
}
