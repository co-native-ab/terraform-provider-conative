package acme

import (
	"fmt"
	"slices"
	"strings"
)

// challengeLabel is the label every DNS-01 challenge record starts with.
const challengeLabel = "_acme-challenge"

// ChallengeFQDN returns the name of the DNS-01 challenge record for an identifier:
// "_acme-challenge." followed by the identifier without a leading "*.".
func ChallengeFQDN(identifier string) string { return challengeLabel + "." + Base(identifier) }

// AzureRelativeName returns the record set name of fqdn relative to zone: "_acme-challenge"
// at the zone apex, "_acme-challenge.<labels>" below it.
func AzureRelativeName(fqdn, zone string) (string, error) {
	if fqdn == challengeLabel+"."+zone {
		return challengeLabel, nil
	}
	suffix := "." + zone
	if !strings.HasSuffix(fqdn, suffix) {
		return "", fmt.Errorf("%q is not inside the zone %q", fqdn, zone)
	}
	return strings.TrimSuffix(fqdn, suffix), nil
}

// ChallengeRecords groups challenge values by record name. A wildcard and its apex
// share one name and so get two values in one record set.
func ChallengeRecords(values map[string]string) map[string][]string {
	out := map[string][]string{}
	for identifier, v := range values {
		fqdn := ChallengeFQDN(identifier)
		if !slices.Contains(out[fqdn], v) {
			out[fqdn] = append(out[fqdn], v)
		}
	}
	for k := range out {
		slices.Sort(out[k])
	}
	return out
}

// AddValues returns the TXT records of a set with the given single-string values added.
// Existing records, including multi-string ones, keep their order and content; a value
// that is already present is not added twice.
func AddValues(existing [][]string, add []string) [][]string {
	out := slices.Clone(existing)
	for _, v := range add {
		if !containsSingle(out, v) {
			out = append(out, []string{v})
		}
	}
	return out
}

// RemoveValues returns the records of a set without the single-string records that
// equal one of the given values. Records of other writers keep their order and
// content. It reports the remaining records; an empty result means the set is empty.
func RemoveValues(existing [][]string, remove []string) [][]string {
	var out [][]string
	for _, rec := range existing {
		if len(rec) == 1 && slices.Contains(remove, rec[0]) {
			continue
		}
		out = append(out, rec)
	}
	return out
}

func containsSingle(records [][]string, v string) bool {
	for _, rec := range records {
		if len(rec) == 1 && rec[0] == v {
			return true
		}
	}
	return false
}
