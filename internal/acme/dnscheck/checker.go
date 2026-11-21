// Package dnscheck waits until challenge records are visible where the certificate
// authority will look for them.
package dnscheck

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"
)

// Checker waits until every value is present in the TXT record of fqdn. zone is the DNS
// zone the record was written to.
type Checker interface {
	Wait(ctx context.Context, fqdn, zone string, values []string) error
}

// Authoritative polls the zone's authoritative name servers directly, which is where a
// certificate authority validates. The zone's NS records are resolved first.
type Authoritative struct {
	// Timeout bounds the whole wait; Interval is the pause between polls.
	Timeout  time.Duration
	Interval time.Duration
	// Resolver resolves the zone's NS records; the system resolver when nil.
	Resolver *net.Resolver
	// Dial connects to a name server's address ("host:53"); the default dialer when nil.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
}

// Default returns the checker the provider uses: two minutes, polling every five seconds.
func Default() Authoritative {
	return Authoritative{Timeout: 2 * time.Minute, Interval: 5 * time.Second}
}

// Wait implements Checker.
func (a Authoritative) Wait(ctx context.Context, fqdn, zone string, values []string) error {
	ctx, cancel := context.WithTimeout(ctx, a.Timeout)
	defer cancel()

	resolver := a.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	nss, err := resolver.LookupNS(ctx, zone)
	if err != nil || len(nss) == 0 {
		return fmt.Errorf("cannot find the name servers of the zone %q: %w", zone, orNoServers(err))
	}
	servers := make([]string, len(nss))
	for i, ns := range nss {
		servers[i] = strings.TrimSuffix(ns.Host, ".")
	}

	var lastMissing error
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			if lastMissing != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return fmt.Errorf("%w (waited %s)", lastMissing, a.Timeout)
			}
			return ctx.Err()
		case <-timer.C:
		}
		lastMissing = a.missing(ctx, servers, fqdn, values)
		if lastMissing == nil {
			return nil
		}
		timer.Reset(a.Interval)
	}
}

func orNoServers(err error) error {
	if err != nil {
		return err
	}
	return errors.New("no NS records")
}

// missing returns an error naming a server and value that is not visible yet, or nil.
func (a Authoritative) missing(ctx context.Context, servers []string, fqdn string, values []string) error {
	for _, server := range servers {
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			addr := net.JoinHostPort(server, "53")
			if a.Dial != nil {
				return a.Dial(ctx, network, addr)
			}
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		}}
		got, err := r.LookupTXT(ctx, fqdn)
		if err != nil {
			var de *net.DNSError
			if !errors.As(err, &de) || !de.IsNotFound {
				return fmt.Errorf("the name server %s cannot be queried for %s: %w", server, fqdn, err)
			}
		}
		for _, v := range values {
			if !slices.Contains(got, v) {
				return fmt.Errorf("the TXT value %q of %s is not visible on the name server %s", v, fqdn, server)
			}
		}
	}
	return nil
}
