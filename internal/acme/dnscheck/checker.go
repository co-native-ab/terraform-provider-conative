// Package dnscheck waits until challenge records are visible where the certificate
// authority will look for them.
//
// The check asks the zone's authoritative name servers directly, with queries that do
// not ask for recursion, and trusts only answers that carry the authoritative-answer
// flag. It therefore needs direct UDP and TCP access to port 53 of those name servers.
// It does not work behind a DNS-intercepting proxy or secure web gateway, which answers
// every query itself; such answers (including SERVFAIL and REFUSED without the flag) are
// recognised by the missing flag and are never taken as proof. When every name server of
// a zone answers SERVFAIL or REFUSED without the flag in the first round, the check fails
// at once; otherwise it runs into its timeout. Both errors say how to turn the check off,
// which is what to do in that case: the certificate authority validates the record by
// itself either way.
package dnscheck

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"golang.org/x/net/dns/dnsmessage"
)

// Record is a TXT record an order wrote: the values expected at fqdn, which is served
// by the zone.
type Record struct {
	FQDN   string
	Zone   string
	Values []string
}

// Checker waits until every record is visible, or fails.
type Checker interface {
	Wait(ctx context.Context, records []Record) error
}

const (
	// DefaultInitialDelay is the pause before the first query: a record written a moment
	// ago is often not served yet, and a negative answer may be cached for a while by
	// whatever sits between the provider and the name servers.
	DefaultInitialDelay = 5 * time.Second
	// DefaultTimeout bounds the polling.
	DefaultTimeout = 2 * time.Minute
	// DefaultInterval is the pause between polls.
	DefaultInterval = 5 * time.Second

	queryTimeout = 5 * time.Second
)

// Authoritative polls the zone's authoritative name servers directly, which is where a
// certificate authority validates. The zone's NS records are resolved first.
type Authoritative struct {
	// InitialDelay is the pause before the first poll. It is not part of Timeout.
	InitialDelay time.Duration
	// Timeout bounds the polling; Interval is the pause between polls.
	Timeout  time.Duration
	Interval time.Duration
	// Resolver resolves the zone's NS records and the addresses of the name servers; the
	// system resolver when nil.
	Resolver *net.Resolver
	// Dial connects to a name server's address ("ip:53"); the default dialer when nil.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
}

// Default returns the checker the provider uses unless it is configured otherwise: a
// five second delay, then polling every five seconds for two minutes.
func Default() Authoritative {
	return Authoritative{InitialDelay: DefaultInitialDelay, Timeout: DefaultTimeout, Interval: DefaultInterval}
}

// DelayOnly does not check anything: it waits the delay once and returns. It is what
// remains of the check when it is turned off.
type DelayOnly struct {
	Delay time.Duration
}

// Wait implements Checker.
func (d DelayOnly) Wait(ctx context.Context, records []Record) error {
	tflog.Debug(ctx, "dns propagation check is off; waiting before the certificate authority validates",
		map[string]any{"delay": d.Delay.String(), "records": len(records)})
	return sleep(ctx, d.Delay)
}

func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// server is one name server of a zone.
type server struct {
	host  string
	addrs []string // resolved lazily
}

// Wait implements Checker.
func (a Authoritative) Wait(ctx context.Context, records []Record) error {
	if len(records) == 0 {
		return nil
	}
	if err := sleep(ctx, a.InitialDelay); err != nil {
		return err
	}
	start := time.Now()
	pctx, cancel := context.WithTimeout(ctx, a.Timeout)
	defer cancel()

	zones := map[string][]*server{}
	for _, r := range records {
		if _, ok := zones[r.Zone]; ok {
			continue
		}
		servers, err := a.nameServers(pctx, r.Zone)
		if err != nil {
			return err
		}
		zones[r.Zone] = servers
		hosts := make([]string, len(servers))
		for i, s := range servers {
			hosts[i] = s.host
		}
		tflog.Debug(ctx, "querying the authoritative name servers of the zone", map[string]any{"zone": r.Zone, "name_servers": hosts})
	}

	var last pollResult
	first := true
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-pctx.Done():
			elapsed := time.Since(start).Round(time.Millisecond)
			tflog.Debug(ctx, "dns propagation check timed out", map[string]any{"elapsed": elapsed.String(), "timeout": a.Timeout.String()})
			if last.err != nil && errors.Is(pctx.Err(), context.DeadlineExceeded) {
				return last.timeoutError(a.Timeout)
			}
			return pctx.Err()
		case <-timer.C:
		}
		last = a.poll(pctx, ctx, zones, records, first)
		first = false
		if last.fatal != nil {
			tflog.Debug(ctx, "dns propagation check failed in the first round", map[string]any{"error": last.fatal.Error()})
			return last.fatal
		}
		if last.err == nil {
			tflog.Debug(ctx, "the challenge records are visible on every authoritative name server",
				map[string]any{"elapsed": time.Since(start).Round(time.Millisecond).String(), "records": len(records)})
			return nil
		}
		timer.Reset(a.Interval)
	}
}

// pollResult is the outcome of one poll: nil err means everything is visible.
type pollResult struct {
	err error
	// nonAuthoritative is true when an answer lacked the authoritative-answer flag.
	nonAuthoritative bool
	// fatal is set in the first round when every name server of a zone answered SERVFAIL
	// or REFUSED without the authoritative-answer flag: waiting longer is pointless.
	fatal error
}

// proxyHint explains answers without the authoritative-answer flag and says how to skip
// the check.
const proxyHint = "The answers did not carry the authoritative-answer flag, so something between this host and the " +
	"name servers (a DNS-intercepting proxy or secure web gateway) answered instead of them, or the name servers " +
	"do not serve the zone. Set dns_propagation_check = false in the provider's acme settings to skip this check " +
	"when DNS is intercepted on this network"

func (p pollResult) timeoutError(timeout time.Duration) error {
	msg := fmt.Sprintf("%v (waited %s)", p.err, timeout)
	if p.nonAuthoritative {
		msg += ". " + proxyHint
	}
	return errors.New(msg)
}

func (a Authoritative) resolver() *net.Resolver {
	if a.Resolver != nil {
		return a.Resolver
	}
	return net.DefaultResolver
}

// nameServers resolves the NS records of a zone.
func (a Authoritative) nameServers(ctx context.Context, zone string) ([]*server, error) {
	nss, err := a.resolver().LookupNS(ctx, absolute(zone))
	if err != nil || len(nss) == 0 {
		return nil, fmt.Errorf("cannot find the name servers of the zone %q: %w", zone, orNoServers(err))
	}
	out := make([]*server, len(nss))
	for i, ns := range nss {
		out[i] = &server{host: strings.TrimSuffix(ns.Host, ".")}
	}
	return out, nil
}

// absolute returns the name with a trailing dot, so that the resolver does not try the
// names of a search list first (for example example.com.corp.local).
func absolute(name string) string { return strings.TrimSuffix(name, ".") + "." }

func orNoServers(err error) error {
	if err != nil {
		return err
	}
	return errors.New("no NS records")
}

// poll checks every record on every name server of its zone. ctx bounds the polling;
// logCtx carries the logger. The first round asks every name server even after one has
// failed, to tell whether all of a zone's servers answer SERVFAIL or REFUSED without the
// authoritative-answer flag.
func (a Authoritative) poll(ctx, logCtx context.Context, zones map[string][]*server, records []Record, first bool) pollResult {
	var res pollResult
	for _, r := range records {
		servers := zones[r.Zone]
		var failing []string // rcodes of SERVFAIL/REFUSED answers without the flag
		for _, s := range servers {
			ans, err := a.ask(ctx, s, r.FQDN)
			switch {
			case err != nil:
				tflog.Debug(logCtx, "a name server could not be queried",
					map[string]any{"name_server": s.host, "name": r.FQDN, "error": err.Error()})
				res.err = fmt.Errorf("the name server %s cannot be queried for %s: %w", s.host, r.FQDN, err)
			case !ans.authoritative:
				tflog.Warn(logCtx, "a DNS answer did not carry the authoritative-answer flag: something between this host and "+
					"the name server (a DNS-intercepting proxy or secure web gateway) answered; the answer is ignored",
					map[string]any{"name_server": s.host, "name": r.FQDN, "authoritative": false, "rcode": ans.rcode})
				res.nonAuthoritative = true
				if ans.failure {
					failing = append(failing, ans.rcode)
				}
				res.err = fmt.Errorf("the name server %s answered %s for %s without the authoritative-answer flag, so the answer is not trusted", s.host, ans.rcode, r.FQDN)
			default:
				var missing string
				for _, v := range r.Values {
					if !slices.Contains(ans.txt, v) {
						missing = v
						break
					}
				}
				tflog.Debug(logCtx, "a name server was queried", map[string]any{
					"name_server": s.host, "name": r.FQDN, "authoritative": true, "visible": missing == "", "rcode": ans.rcode,
				})
				if missing != "" {
					res.err = fmt.Errorf("the TXT value %q of %s is not visible on the name server %s", missing, r.FQDN, s.host)
				}
			}
			if res.err != nil && !res.nonAuthoritative && !first {
				return res // report the first server that lacks the value
			}
		}
		if first && res.fatal == nil && len(servers) > 0 && len(failing) == len(servers) {
			res.fatal = fmt.Errorf("every name server of the zone %q answered %s for %s without the authoritative-answer flag. %s",
				r.Zone, strings.Join(uniqueSorted(failing), " or "), r.FQDN, proxyHint)
		}
	}
	return res
}

func uniqueSorted(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return slices.Compact(out)
}

type answer struct {
	authoritative bool
	rcode         string
	txt           []string
	// failure is true for a SERVFAIL or REFUSED answer without the authoritative-answer
	// flag, which is how a DNS-intercepting proxy may refuse to pass a query on.
	failure bool
}

// ask queries one name server for the TXT records of a name: over UDP, with recursion
// not desired, and over TCP when the answer is truncated. It tries the addresses of the
// host in order and returns the first answer. A SERVFAIL or REFUSED without the
// authoritative-answer flag is kept only when no other address gives a better answer.
func (a Authoritative) ask(ctx context.Context, s *server, fqdn string) (answer, error) {
	if len(s.addrs) == 0 {
		addrs, err := a.resolver().LookupHost(ctx, absolute(s.host))
		if err != nil || len(addrs) == 0 {
			return answer{}, fmt.Errorf("cannot resolve the name server: %w", orNoServers(err))
		}
		s.addrs = addrs
	}
	var errs []error
	var failed *answer
	for _, addr := range s.addrs {
		ans, err := a.exchange(ctx, net.JoinHostPort(addr, "53"), fqdn)
		switch {
		case err != nil:
			errs = append(errs, err)
		case ans.failure:
			if failed == nil {
				failed = &ans
			}
		default:
			return ans, nil
		}
	}
	if failed != nil {
		return *failed, nil
	}
	return answer{}, errors.Join(errs...)
}

func (a Authoritative) dial(ctx context.Context, network, address string) (net.Conn, error) {
	if a.Dial != nil {
		return a.Dial(ctx, network, address)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

func (a Authoritative) exchange(ctx context.Context, address, fqdn string) (answer, error) {
	name, err := dnsmessage.NewName(absolute(fqdn))
	if err != nil {
		return answer{}, fmt.Errorf("invalid name: %w", err)
	}
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return answer{}, err
	}
	id := binary.BigEndian.Uint16(idb[:])
	// RecursionDesired is false: the name server must answer from its own data.
	query := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: false},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}},
	}
	wire, err := query.Pack()
	if err != nil {
		return answer{}, err
	}
	resp, err := a.roundTrip(ctx, "udp", address, wire)
	if err != nil {
		return answer{}, err
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(resp); err != nil {
		return answer{}, fmt.Errorf("unreadable answer: %w", err)
	}
	if msg.ID != id || !msg.Response {
		return answer{}, errors.New("the answer does not match the query")
	}
	if msg.Truncated {
		resp, err = a.roundTrip(ctx, "tcp", address, wire)
		if err != nil {
			return answer{}, err
		}
		msg = dnsmessage.Message{}
		if err := msg.Unpack(resp); err != nil {
			return answer{}, fmt.Errorf("unreadable answer: %w", err)
		}
		if msg.ID != id || !msg.Response {
			return answer{}, errors.New("the answer does not match the query")
		}
	}
	out := answer{authoritative: msg.Authoritative, rcode: rcodeName(msg.RCode)}
	switch msg.RCode {
	case dnsmessage.RCodeSuccess, dnsmessage.RCodeNameError:
	case dnsmessage.RCodeServerFailure, dnsmessage.RCodeRefused:
		if !msg.Authoritative {
			// Not an answer of the name server: treated like any answer without the flag.
			out.failure = true
			return out, nil
		}
		return answer{}, fmt.Errorf("the name server answered %s", rcodeName(msg.RCode))
	default:
		return answer{}, fmt.Errorf("the name server answered %s", rcodeName(msg.RCode))
	}
	for _, r := range msg.Answers {
		if txt, ok := r.Body.(*dnsmessage.TXTResource); ok {
			out.txt = append(out.txt, strings.Join(txt.TXT, ""))
		}
	}
	return out, nil
}

// rcodeName spells a response code the way DNS tools do.
func rcodeName(c dnsmessage.RCode) string {
	switch c {
	case dnsmessage.RCodeSuccess:
		return "NOERROR"
	case dnsmessage.RCodeFormatError:
		return "FORMERR"
	case dnsmessage.RCodeServerFailure:
		return "SERVFAIL"
	case dnsmessage.RCodeNameError:
		return "NXDOMAIN"
	case dnsmessage.RCodeNotImplemented:
		return "NOTIMP"
	case dnsmessage.RCodeRefused:
		return "REFUSED"
	}
	return c.String()
}

// roundTrip sends one message and reads one answer, over UDP or TCP (with the two-byte
// length prefix).
func (a Authoritative) roundTrip(ctx context.Context, network, address string, wire []byte) ([]byte, error) {
	conn, err := a.dial(ctx, network, address)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	deadline := time.Now().Add(queryTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	if network == "tcp" {
		if len(wire) > math.MaxUint16 {
			return nil, errors.New("the query is too long")
		}
		framed := binary.BigEndian.AppendUint16(nil, uint16(len(wire))) //nolint:gosec // bounded just above
		if _, err := conn.Write(append(framed, wire...)); err != nil {
			return nil, err
		}
		var lb [2]byte
		if _, err := io.ReadFull(conn, lb[:]); err != nil {
			return nil, err
		}
		buf := make([]byte, binary.BigEndian.Uint16(lb[:]))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return nil, err
		}
		return buf, nil
	}
	if _, err := conn.Write(wire); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}
