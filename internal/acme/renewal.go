package acme

import (
	"fmt"
	"slices"
	"time"
)

const day = 24 * time.Hour

// NeedsOrder decides whether a certificate must be ordered again and says why. The
// current time is an input; this function never reads a clock.
//
// An order is needed when the certificate expires within minDays days (the boundary
// counts), when Key Vault's current version differs from the version this resource last
// issued, or when the names, the key type or the certificate authority changed.
func NeedsOrder(now, notAfter time.Time, minDays int64, version, issuedVersion string, namesOrKeyChanged bool) (bool, string) {
	switch {
	case namesOrKeyChanged:
		return true, "the names, the key type or the certificate authority changed"
	case version != issuedVersion:
		return true, fmt.Sprintf("the certificate's current version %q was added outside Terraform (last issued: %q)", version, issuedVersion)
	case !now.Add(time.Duration(minDays) * day).Before(notAfter):
		return true, fmt.Sprintf("the certificate expires at %s, within min_days_remaining (%d days)", notAfter.UTC().Format(time.RFC3339), minDays)
	}
	return false, ""
}

// InsideWindow reports whether a certificate is already inside its renewal window.
func InsideWindow(now, notAfter time.Time, minDays int64) bool {
	return !now.Add(time.Duration(minDays) * day).Before(notAfter)
}

// NamesChanged compares the configured common name and alternative names with the
// certificate's. The names are compared as sets: order and duplicates do not matter and
// a missing list equals an empty one. The common name is compared on its own.
func NamesChanged(cfgCN string, cfgSANs []string, stateCN string, stateSANs []string) bool {
	if cfgCN != stateCN {
		return true
	}
	return !slices.Equal(sortedSet(cfgSANs), sortedSet(stateSANs))
}

// KeyTypeChanged reports whether the configured key type differs from the certificate's.
func KeyTypeChanged(cfg, state string) bool { return cfg != state }

func sortedSet(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return slices.Compact(out)
}
