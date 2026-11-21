// Package dnsstore is the DNS the fakes share: the Azure DNS and Cloudflare fakes write
// TXT values into it, the ACME fake reads them to validate challenges, and the
// propagation check of the tests reads it too.
package dnsstore

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/co-native-ab/terraform-provider-conative/internal/acme/dnscheck"
)

// Store maps a fully qualified name to its TXT values.
type Store struct {
	mu    sync.Mutex
	txt   map[string][]string
	never map[string]bool
}

// New returns an empty store.
func New() *Store { return &Store{txt: map[string][]string{}, never: map[string]bool{}} }

func norm(fqdn string) string { return strings.ToLower(strings.TrimSuffix(fqdn, ".")) }

// Set replaces the values of a name; no values removes the name.
func (s *Store) Set(fqdn string, values []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(values) == 0 {
		delete(s.txt, norm(fqdn))
		return
	}
	s.txt[norm(fqdn)] = slices.Clone(values)
}

// Add adds one value to a name.
func (s *Store) Add(fqdn, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.txt[norm(fqdn)] = append(s.txt[norm(fqdn)], value)
}

// Remove removes one value from a name.
func (s *Store) Remove(fqdn, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := norm(fqdn)
	s.txt[n] = slices.DeleteFunc(s.txt[n], func(v string) bool { return v == value })
	if len(s.txt[n]) == 0 {
		delete(s.txt, n)
	}
}

// Values returns the values of a name.
func (s *Store) Values(fqdn string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.txt[norm(fqdn)])
}

// All returns every name that has values.
func (s *Store) All() map[string][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string][]string, len(s.txt))
	for k, v := range s.txt {
		out[k] = slices.Clone(v)
	}
	return out
}

// NeverPropagate makes the checker report the name as never visible.
func (s *Store) NeverPropagate(fqdn string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.never[norm(fqdn)] = true
}

// Reset removes every value and every NeverPropagate setting.
func (s *Store) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.txt = map[string][]string{}
	s.never = map[string]bool{}
}

// Checker returns a propagation check that reads the store.
func (s *Store) Checker() dnscheck.Checker { return checker{s} }

type checker struct{ s *Store }

func (c checker) Wait(ctx context.Context, records []dnscheck.Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, r := range records {
		c.s.mu.Lock()
		never := c.s.never[norm(r.FQDN)]
		c.s.mu.Unlock()
		if never {
			return fmt.Errorf("the TXT value %q of %s is not visible on the name server (test store)", r.Values[0], r.FQDN)
		}
		have := c.s.Values(r.FQDN)
		for _, v := range r.Values {
			if !slices.Contains(have, v) {
				return fmt.Errorf("the TXT value %q of %s is not visible on the name server (test store)", v, r.FQDN)
			}
		}
	}
	return nil
}
