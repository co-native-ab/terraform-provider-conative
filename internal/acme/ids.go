package acme

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var (
	nameRE    = regexp.MustCompile(`^[0-9A-Za-z-]{1,127}$`)
	versionRE = regexp.MustCompile(`^[0-9A-Za-z]+$`)
	guidRE    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	rgRE      = regexp.MustCompile(`^[0-9A-Za-z_().-]{1,90}$`)
	emailRE   = regexp.MustCompile(`^[^\s@,]+@[^\s@,]+$`)
)

// ParseVaultURL validates a Key Vault URL, https://<host>[:port] with an optional single
// trailing "/", and returns it without the trailing slash and with a lower-case host.
func ParseVaultURL(s string) (string, error) {
	const msg = "must be a Key Vault URL such as https://example.vault.azure.net/"
	u, err := parseHTTPS(s)
	if err != nil {
		return "", fmt.Errorf("%q %s", s, msg)
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return "", fmt.Errorf("%q %s", s, msg)
	}
	return "https://" + strings.ToLower(u.Host), nil
}

func parseHTTPS(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Opaque != "" {
		return nil, errors.New("not an https URL")
	}
	if strings.ContainsAny(s, " \t\r\n|") {
		return nil, errors.New("contains forbidden characters")
	}
	return u, nil
}

// VaultURLEqual reports whether two Key Vault URLs name the same vault, ignoring the
// case of the host and one trailing "/". Invalid URLs are never equal.
func VaultURLEqual(a, b string) bool {
	pa, errA := ParseVaultURL(a)
	pb, errB := ParseVaultURL(b)
	return errA == nil && errB == nil && pa == pb
}

// ValidateServerURL checks an ACME directory URL: https, a host, an optional port and
// path, no user information, query, fragment or "|".
func ValidateServerURL(s string) error {
	u, err := parseHTTPS(s)
	if err != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return fmt.Errorf("%q must be an https URL", s)
	}
	return nil
}

// ValidateCertificateName checks a Key Vault certificate name.
func ValidateCertificateName(s string) error {
	if !nameRE.MatchString(s) {
		return fmt.Errorf("%q must be 1 to 127 letters, digits or hyphens", s)
	}
	return nil
}

// KeyRef is a versioned Key Vault key.
type KeyRef struct {
	Vault   string // https://host[:port], lower-case host, no trailing slash
	Name    string
	Version string
}

// String formats the key ID.
func (k KeyRef) String() string { return k.Vault + "/keys/" + k.Name + "/" + k.Version }

// ParseKeyID parses a versioned key ID such as https://example.vault.azure.net/keys/name/version.
func ParseKeyID(s string) (KeyRef, error) {
	const msg = "must be a versioned Key Vault key ID (https://<vault>/keys/<name>/<version>)"
	u, err := parseHTTPS(s)
	if err != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return KeyRef{}, fmt.Errorf("%q %s", s, msg)
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) == 2 && parts[0] == "keys" && nameRE.MatchString(parts[1]) {
		return KeyRef{}, fmt.Errorf("%q has no version; use the versioned ID, for example the id attribute of azurerm_key_vault_key: %s", s, msg)
	}
	if len(parts) != 3 || parts[0] != "keys" || !nameRE.MatchString(parts[1]) || !versionRE.MatchString(parts[2]) {
		return KeyRef{}, fmt.Errorf("%q %s", s, msg)
	}
	return KeyRef{Vault: "https://" + strings.ToLower(u.Host), Name: parts[1], Version: parts[2]}, nil
}

// CertificateID formats the versionless certificate ID.
func CertificateID(vault, name string) string { return vault + "/certificates/" + name }

// SecretID formats the versionless secret ID.
func SecretID(vault, name string) string { return vault + "/secrets/" + name }

// ParseCertificateImportID parses a versionless certificate ID.
func ParseCertificateImportID(s string) (vault, name string, err error) {
	const msg = "must be a versionless Key Vault certificate ID (https://<vault>/certificates/<name>)"
	u, perr := parseHTTPS(s)
	if perr != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return "", "", fmt.Errorf("%q %s", s, msg)
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) != 2 || parts[0] != "certificates" || !nameRE.MatchString(parts[1]) {
		return "", "", fmt.Errorf("%q %s", s, msg)
	}
	return "https://" + strings.ToLower(u.Host), parts[1], nil
}

// RegistrationID formats the ID of a registration: <server_url>|<account_key_id>.
func RegistrationID(serverURL, accountKeyID string) string { return serverURL + "|" + accountKeyID }

// ParseRegistrationID splits and validates a registration ID.
func ParseRegistrationID(s string) (serverURL string, key KeyRef, err error) {
	const msg = "must be <server_url>|<account_key_id>"
	server, keyID, ok := strings.Cut(s, "|")
	if !ok || strings.Contains(keyID, "|") {
		return "", KeyRef{}, fmt.Errorf("%q %s", s, msg)
	}
	if err := ValidateServerURL(server); err != nil {
		return "", KeyRef{}, fmt.Errorf("%q %s: %w", s, msg, err)
	}
	k, err := ParseKeyID(keyID)
	if err != nil {
		return "", KeyRef{}, fmt.Errorf("%q %s: %w", s, msg, err)
	}
	return server, k, nil
}

// ValidateSubscriptionID checks that s is a canonical GUID.
func ValidateSubscriptionID(s string) error {
	if !guidRE.MatchString(s) {
		return fmt.Errorf("%q must be a GUID", s)
	}
	return nil
}

// ValidateResourceGroup checks an Azure resource group name.
func ValidateResourceGroup(s string) error {
	if !rgRE.MatchString(s) || strings.HasSuffix(s, ".") {
		return fmt.Errorf("%q must be a resource group name", s)
	}
	return nil
}

// ValidateEmail checks a contact address; it is sent as a mailto: URL.
func ValidateEmail(s string) error {
	if !emailRE.MatchString(s) {
		return fmt.Errorf("%q must be an e-mail address", s)
	}
	return nil
}
