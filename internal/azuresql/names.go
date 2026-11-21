package azuresql

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// MaxNameLength is the longest identifier SQL Server accepts (sysname), counted in
// UTF-16 code units.
const MaxNameLength = 128

// DefaultPort is the TCP port used when a server name has no explicit port.
const DefaultPort = 1433

// ErrInvalidName is returned for names SQL Server cannot hold as an identifier.
var ErrInvalidName = errors.New("must be 1 to 128 characters and contain no NUL")

// ValidateName reports whether s is usable as a database, user, role, schema or
// principal name: 1 to 128 UTF-16 code units, valid UTF-8, and no NUL.
func ValidateName(s string) error {
	if s == "" || !utf8.ValidString(s) || strings.ContainsRune(s, 0) {
		return ErrInvalidName
	}
	units := 0
	for _, r := range s {
		units += utf16.RuneLen(r)
	}
	if units > MaxNameLength {
		return ErrInvalidName
	}
	return nil
}

// QuoteName returns s as a bracket-quoted identifier with every closing bracket
// doubled, the same result as the T-SQL QUOTENAME function. It rejects names that
// ValidateName rejects.
func QuoteName(s string) (string, error) {
	if err := ValidateName(s); err != nil {
		return "", err
	}
	return "[" + strings.ReplaceAll(s, "]", "]]") + "]", nil
}

// ErrInvalidServer is returned for server names that are not a host with an optional port.
var ErrInvalidServer = errors.New("must be a host name, optionally with :port")

// ParseServer splits a server name of the form host or host:port into its host and
// port. The port defaults to DefaultPort. Anything else, such as a scheme, a path,
// spaces, ';', '=' or ',', is rejected so that no configuration value can carry
// connection options.
func ParseServer(s string) (host string, port int, err error) {
	host, port = s, DefaultPort
	if i := strings.LastIndex(s, ":"); i >= 0 {
		host = s[:i]
		portText := s[i+1:]
		if portText == "" || len(portText) > 5 {
			return "", 0, ErrInvalidServer
		}
		for _, r := range portText {
			if r < '0' || r > '9' {
				return "", 0, ErrInvalidServer
			}
		}
		port, err = strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return "", 0, fmt.Errorf("%w (port must be 1 to 65535)", ErrInvalidServer)
		}
	}
	if !validHost(host) {
		return "", 0, ErrInvalidServer
	}
	return host, port, nil
}

func validHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, r := range h {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}
