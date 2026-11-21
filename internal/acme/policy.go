package acme

import (
	"fmt"
	"strings"
)

// Policy is the body of a Key Vault certificate create request.
type Policy struct {
	Policy     PolicyBody `json:"policy"`
	Attributes Attributes `json:"attributes"`
}

// PolicyBody is the certificate policy.
type PolicyBody struct {
	KeyProps        KeyPropsBody    `json:"key_props"`
	SecretProps     SecretProps     `json:"secret_props"`
	X509Props       X509Props       `json:"x509_props"`
	Issuer          IssuerRef       `json:"issuer"`
	LifetimeActions []LifetimeEntry `json:"lifetime_actions"`
}

// KeyPropsBody are the key properties of a policy.
type KeyPropsBody struct {
	Exportable bool   `json:"exportable"`
	KTY        string `json:"kty"`
	KeySize    int    `json:"key_size,omitempty"`
	Curve      string `json:"crv,omitempty"`
	ReuseKey   bool   `json:"reuse_key"`
}

// SecretProps are the secret properties of a policy.
type SecretProps struct {
	ContentType string `json:"contentType"`
}

// X509Props are the subject and names of a policy.
type X509Props struct {
	Subject string `json:"subject"`
	SANs    SANs   `json:"sans"`
}

// SANs are the subject alternative names of a policy.
type SANs struct {
	DNSNames []string `json:"dns_names"`
}

// IssuerRef names the issuer of a policy.
type IssuerRef struct {
	Name string `json:"name"`
}

// LifetimeEntry is a lifetime action of a policy. The provider sends none.
type LifetimeEntry struct{}

// Attributes are the certificate attributes of a create request.
type Attributes struct {
	Enabled bool `json:"enabled"`
}

// UnknownIssuer is the issuer name that makes Key Vault generate a key and a signing
// request and wait for a certificate to be merged.
const UnknownIssuer = "Unknown"

// CreatePolicy builds the create request body for a certificate: issuer Unknown, an
// exportable key that is new for every version, the subject CN and the identifiers as
// DNS names, no lifetime actions, PKCS #12 content.
func CreatePolicy(commonName string, identifiers []string, keyType string) (Policy, error) {
	props, err := KeyPropsFor(keyType)
	if err != nil {
		return Policy{}, err
	}
	return Policy{
		Policy: PolicyBody{
			KeyProps: KeyPropsBody{
				Exportable: true, KTY: props.KTY, KeySize: props.KeySize, Curve: props.Curve, ReuseKey: false,
			},
			SecretProps:     SecretProps{ContentType: "application/x-pkcs12"},
			X509Props:       X509Props{Subject: "CN=" + commonName, SANs: SANs{DNSNames: identifiers}},
			Issuer:          IssuerRef{Name: UnknownIssuer},
			LifetimeActions: []LifetimeEntry{},
		},
		Attributes: Attributes{Enabled: true},
	}, nil
}

// VaultState is what the pre-check of an order has read from Key Vault.
type VaultState struct {
	// HasIssuedVersion is true when the certificate has a version with an issued
	// certificate.
	HasIssuedVersion bool
	// HasPending is true when Key Vault holds a pending-operation record. It keeps the
	// record after the operation has finished.
	HasPending bool
	// PendingIssuer is the issuer of the pending operation.
	PendingIssuer string
	// PendingStatus is the status of the pending operation (for example "inProgress",
	// "completed", "failed" or "cancelled"). Empty counts as in progress.
	PendingStatus string
}

// PendingInProgress reports whether the pending operation is still running. Key Vault
// keeps the record of a finished operation; only a running one blocks an order.
func (s VaultState) PendingInProgress() bool {
	return s.HasPending && (s.PendingStatus == "" || strings.EqualFold(s.PendingStatus, "inProgress"))
}

// PrepareKeyVault decides what to do before an order. When creating, an issued version
// means the certificate already exists and must be imported instead. A pending
// operation that is not in progress (completed, failed or cancelled, of any issuer) is
// only a leftover record: it does not block, and is deleted before an order. One that
// is in progress with issuer Unknown is left over from an earlier attempt and must be
// deleted; one in progress of another issuer belongs to someone else and fails the
// order.
func PrepareKeyVault(s VaultState, creating bool, importID string) (deletePending bool, err error) {
	if creating && s.HasIssuedVersion {
		return false, fmt.Errorf("the Key Vault certificate already exists; import it with the ID %s", importID)
	}
	if !s.HasPending {
		return false, nil
	}
	if !s.PendingInProgress() {
		return true, nil
	}
	if s.PendingIssuer != UnknownIssuer {
		return false, fmt.Errorf("the Key Vault certificate has an operation in progress of issuer %q; wait for it to finish or cancel it before ordering", s.PendingIssuer)
	}
	return true, nil
}
