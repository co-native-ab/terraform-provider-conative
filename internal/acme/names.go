package acme

import (
	"errors"
	"fmt"
	"strings"
)

const maxNameLength = 253

// maxCommonNameLength is the longest subject common name RFC 5280 allows (ub-common-name).
// Some certificate authorities drop a longer one from the certificate, and the names
// remain covered by the subject alternative names, but the resource requires a
// common name that fits so that it can be read back.
const maxCommonNameLength = 64

// ValidateCommonName checks that a common name fits in a certificate's subject.
func ValidateCommonName(s string) error {
	if len(s) > maxCommonNameLength {
		return fmt.Errorf("%q is %d characters long; a common name can have at most %d", s, len(s), maxCommonNameLength)
	}
	return nil
}

// ValidateIdentifier checks a certificate name: lower-case LDH labels of 1 to 63
// characters, at least two labels, at most 253 characters in total, no trailing dot,
// and an optional single leading "*." wildcard. Unicode names must be given in their
// "xn--" form.
func ValidateIdentifier(s string) error {
	base := strings.TrimPrefix(s, "*.")
	if err := validateDNSName(base); err != nil {
		if lower := strings.ToLower(s); lower != s && validateDNSName(strings.TrimPrefix(lower, "*.")) == nil {
			return fmt.Errorf("%q must be lower case; use %q", s, lower)
		}
		return fmt.Errorf("%q must be a lower-case DNS name, optionally starting with *.: %w", s, err)
	}
	return nil
}

// ValidateMatchDomain checks an entry of match_domains or a zone name: a DNS name
// without a wildcard.
func ValidateMatchDomain(s string) error {
	if strings.Contains(s, "*") {
		return fmt.Errorf("%q must be a DNS name without a wildcard", s)
	}
	if err := validateDNSName(s); err != nil {
		if lower := strings.ToLower(s); lower != s && validateDNSName(lower) == nil {
			return fmt.Errorf("%q must be lower case; use %q", s, lower)
		}
		return fmt.Errorf("%q must be a lower-case DNS name: %w", s, err)
	}
	return nil
}

func validateDNSName(s string) error {
	if s == "" {
		return errors.New("is empty")
	}
	if len(s) > maxNameLength {
		return fmt.Errorf("is longer than %d characters", maxNameLength)
	}
	if strings.HasSuffix(s, ".") {
		return errors.New("has a trailing dot")
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return errors.New("needs at least two labels")
	}
	for _, l := range labels {
		if l == "" {
			return errors.New("has an empty label")
		}
		if len(l) > 63 {
			return fmt.Errorf("has a label longer than 63 characters")
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return errors.New("has a label that starts or ends with a hyphen")
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return fmt.Errorf("contains the character %q, which is not allowed", string(rune(c)))
			}
		}
	}
	return nil
}

// Base returns an identifier without its leading "*.".
func Base(identifier string) string { return strings.TrimPrefix(identifier, "*.") }

// Identifiers returns the names of a certificate, common name first, and rejects
// invalid names, duplicates and a common name repeated among the alternative names.
func Identifiers(commonName string, sans []string) ([]string, error) {
	if err := ValidateIdentifier(commonName); err != nil {
		return nil, fmt.Errorf("common_name: %w", err)
	}
	if err := ValidateCommonName(commonName); err != nil {
		return nil, fmt.Errorf("common_name: %w", err)
	}
	seen := map[string]bool{commonName: true}
	out := []string{commonName}
	for _, s := range sans {
		if err := ValidateIdentifier(s); err != nil {
			return nil, fmt.Errorf("subject_alternative_names: %w", err)
		}
		if s == commonName {
			return nil, fmt.Errorf("subject_alternative_names: %q is the common_name, which is always a subject alternative name; do not repeat it", s)
		}
		if seen[s] {
			return nil, fmt.Errorf("subject_alternative_names: %q is listed more than once", s)
		}
		seen[s] = true
		out = append(out, s)
	}
	return out, nil
}
