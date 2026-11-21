package azuresql

import (
	"strings"
	"testing"
)

func TestQuoteName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in, want string
	}{
		{"app", "[app]"},
		{"a]b", "[a]]b]"},
		{"]", "[]]]"},
		{"]]", "[]]]]]"},
		{"o'brien", "[o'brien]"},
		{"x; DROP TABLE y; --", "[x; DROP TABLE y; --]"},
		{"ops]; DROP TABLE x; --", "[ops]]; DROP TABLE x; --]"},
		{"with space", "[with space]"},
		{"naïve-名前-😀", "[naïve-名前-😀]"},
		{"[bracketed]", "[[bracketed]]]"},
	}
	for _, tt := range tests {
		got, err := QuoteName(tt.in)
		if err != nil {
			t.Errorf("QuoteName(%q) failed: %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("QuoteName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestValidateName(t *testing.T) {
	t.Parallel()

	// 😀 is a surrogate pair: two UTF-16 code units.
	valid := []string{
		"a",
		strings.Repeat("a", 128),
		strings.Repeat("😀", 64),
		strings.Repeat("a", 126) + "😀",
	}
	for _, s := range valid {
		if err := ValidateName(s); err != nil {
			t.Errorf("ValidateName(%.20q, %d bytes) = %v, want nil", s, len(s), err)
		}
	}

	invalid := map[string]string{
		"empty":             "",
		"NUL":               "a\x00b",
		"129 units":         strings.Repeat("a", 129),
		"surrogate overrun": strings.Repeat("a", 127) + "😀",
		"65 pairs":          strings.Repeat("😀", 65),
		"invalid UTF-8":     "a\xffb",
	}
	for name, s := range invalid {
		if err := ValidateName(s); err == nil {
			t.Errorf("ValidateName(%s) = nil, want error", name)
		}
		if _, err := QuoteName(s); err == nil {
			t.Errorf("QuoteName(%s) = nil error, want error", name)
		}
	}
}

func TestParseServer(t *testing.T) {
	t.Parallel()

	valid := []struct {
		in   string
		host string
		port int
	}{
		{"example.database.windows.net", "example.database.windows.net", 1433},
		{"example.database.windows.net:1433", "example.database.windows.net", 1433},
		{"localhost:14330", "localhost", 14330},
		{"127.0.0.1:65535", "127.0.0.1", 65535},
		{"10.0.0.4", "10.0.0.4", 1433},
		{"my_host-1", "my_host-1", 1433},
	}
	for _, tt := range valid {
		host, port, err := ParseServer(tt.in)
		if err != nil || host != tt.host || port != tt.port {
			t.Errorf("ParseServer(%q) = %q, %d, %v; want %q, %d, nil", tt.in, host, port, err, tt.host, tt.port)
		}
	}

	invalid := []string{
		"",
		"tcp://example.com",
		"example.com/path",
		"example.com db",
		"example.com;Encrypt=false",
		"example.com,1433",
		"example.com=1",
		"example.com:0",
		"example.com:65536",
		"example.com:",
		"example.com:abc",
		"example.com:-1",
		":1433",
		"a:b:c",
		"exa\tmple.com",
	}
	for _, s := range invalid {
		if _, _, err := ParseServer(s); err == nil {
			t.Errorf("ParseServer(%q) = nil error, want error", s)
		}
	}
}
