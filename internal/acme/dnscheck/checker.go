// Package dnscheck waits until challenge records are visible where the certificate
// authority will look for them.
//
// The check asks the zone's authoritative name servers directly, with queries that do
// not ask for recursion, and trusts only answers that carry the authoritative-answer
// flag. It therefore needs direct UDP and TCP access to port 53 of those name servers.
// It does not work behind a DNS-intercepting proxy or secure web gateway, which answers
// every query itself; such answers are recognised by the missing flag, are never taken
// as proof, and make the check run into its timeout. Turn the check off in that case:
// the certificate authority validates the record by itself either way.
package dnscheck

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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
		last = a.poll(pctx, ctx, zones, records)
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
}

func (p pollResult) timeoutError(timeout time.Duration) error {
	msg := fmt.Sprintf("%v (waited %s)", p.err, timeout)
	if p.nonAuthoritative {
		msg += ". The answers did not carry the authoritative-answer flag, so something between this host and the " +
			"name servers (a DNS-intercepting proxy or secure web gateway) answered instead of them. " +
			"Set dns_propagation_check = false in the provider's acme settings to skip this check"
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
// logCtx carries the logger.
func (a Authoritative) poll(ctx, logCtx context.Context, zones map[string][]*server, records []Record) pollResult {
	var res pollResult
	for _, r := range records {
		for _, s := range zones[r.Zone] {
			ans, err := a.ask(ctx, s, r.FQDN)
			switch {
			case err != nil:
				tflog.Debug(logCtx, "a name server could not be queried",
					map[string]any{"name_server": s.host, "name": r.FQDN, "error": err.Error()})
				res.err = fmt.Errorf("the name server %s cannot be queried for %s: %w", s.host, r.FQDN, err)
			case !ans.authoritative:
				tflog.Warn(logCtx, "a DNS answer did not carry the authoritative-answer flag: something between this host and "+
					"the name server (a DNS-intercepting proxy or secure web gateway) answered; the answer is ignored",
					map[string]any{"name_server": s.host, "name": r.FQDN, "authoritative": false})
				res.nonAuthoritative = true
				res.err = fmt.Errorf("the name server %s answered for %s without the authoritative-answer flag, so the answer is not trusted", s.host, r.FQDN)
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
			if res.err != nil && !res.nonAuthoritative {
				return res // report the first server that lacks the value
			}
		}
	}
	return res
}

type answer struct {
	authoritative bool
	rcode         string
	txt           []string
}

// ask queries one name server for the TXT records of a name: over UDP, with recursion
// not desired, and over TCP when the answer is truncated. It tries the addresses of the
// host in order and returns the first answer.
func (a Authoritative) ask(ctx context.Context, s *server, fqdn string) (answer, error) {
	if len(s.addrs) == 0 {
		addrs, err := a.resolver().LookupHost(ctx, absolute(s.host))
		if err != nil || len(addrs) == 0 {
			return answer{}, fmt.Errorf("cannot resolve the name server: %w", orNoServers(err))
		}
		s.addrs = addrs
	}
	var errs []error
	for _, addr := range s.addrs {
		ans, err := a.exchange(ctx, net.JoinHostPort(addr, "53"), fqdn)
		if err == nil {
			return ans, nil
		}
		errs = append(errs, err)
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
	switch msg.RCode {
	case dnsmessage.RCodeSuccess, dnsmessage.RCodeNameError:
	default:
		return answer{}, fmt.Errorf("the name server answered %s", msg.RCode)
	}
	out := answer{authoritative: msg.Authoritative, rcode: msg.RCode.String()}
	for _, r := range msg.Answers {
		if txt, ok := r.Body.(*dnsmessage.TXTResource); ok {
			out.txt = append(out.txt, strings.Join(txt.TXT, ""))
		}
	}
	return out, nil
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
		framed := binary.BigEndian.AppendUint16(nil, uint16(len(wire)))
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
