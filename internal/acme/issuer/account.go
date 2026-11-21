// Package issuer runs the ACME protocol for the provider: finding, creating and
// updating an account, running an order whose private key is generated in Key Vault, and
// revoking a certificate. It is the only package that imports golang.org/x/crypto/acme.
// It sequences steps and cleans up after failures; decisions belong to internal/acme.
package issuer

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	xacme "golang.org/x/crypto/acme"
)

// UserAgent is sent with every request to the certificate authority.
const UserAgent = "terraform-provider-conative"

// maxRetries is how often a request that failed with a temporary error is repeated.
const maxRetries = 3

// ErrNoAccount means the certificate authority has no account for the key.
var ErrNoAccount = errors.New("the certificate authority has no account for this key")

// Registration is what the protocol needs of an account: the directory, the signer
// whose key is the account key, and the HTTP client.
type Registration struct {
	ServerURL  string
	Signer     crypto.Signer
	HTTPClient *http.Client
	// RetryBase is the first pause before a repeated request (default one second); it
	// doubles for every further attempt. Tests shorten it.
	RetryBase time.Duration
}

// Account is an account at the certificate authority.
type Account struct {
	URL     string
	Contact []string
}

func (r Registration) client() *xacme.Client {
	return &xacme.Client{
		Key:          r.Signer,
		DirectoryURL: r.ServerURL,
		HTTPClient:   r.HTTPClient,
		UserAgent:    UserAgent,
		RetryBackoff: r.backoff,
	}
}

// backoff bounds the library's retries: at most maxRetries repeats, honouring
// Retry-After up to 30 seconds, otherwise base, 2*base, 4*base.
func (r Registration) backoff(n int, _ *http.Request, res *http.Response) time.Duration {
	if n > maxRetries {
		return 0
	}
	if res != nil {
		if v := res.Header.Get("Retry-After"); v != "" {
			if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
				return min(time.Duration(secs)*time.Second, 30*time.Second)
			}
		}
	}
	base := r.RetryBase
	if base <= 0 {
		base = time.Second
	}
	return base << (n - 1)
}

func toAccount(a *xacme.Account) Account { return Account{URL: a.URI, Contact: a.Contact} }

// Lookup finds the account for the key without creating anything. It returns
// ErrNoAccount when there is none.
func Lookup(ctx context.Context, r Registration) (Account, error) {
	c := r.client()
	a, err := c.GetReg(ctx, "")
	if errors.Is(err, xacme.ErrNoAccount) {
		return Account{}, ErrNoAccount
	}
	if err != nil {
		return Account{}, fmt.Errorf("cannot look up the account: %w", err)
	}
	return toAccount(a), nil
}

// Register creates an account for the key, agreeing to the terms of service. When the
// account already exists it is returned.
func Register(ctx context.Context, r Registration, email string) (Account, error) {
	c := r.client()
	acct := &xacme.Account{}
	if email != "" {
		acct.Contact = []string{"mailto:" + email}
	}
	a, err := c.Register(ctx, acct, xacme.AcceptTOS)
	if errors.Is(err, xacme.ErrAccountAlreadyExists) {
		return Lookup(ctx, r)
	}
	if err != nil {
		return Account{}, fmt.Errorf("cannot create the account: %w", err)
	}
	return toAccount(a), nil
}

// UpdateContact sets the contact address of an account.
func UpdateContact(ctx context.Context, r Registration, accountURL, email string) (Account, error) {
	c := r.client()
	c.KID = xacme.KeyID(accountURL)
	a, err := c.UpdateReg(ctx, &xacme.Account{Contact: []string{"mailto:" + email}})
	if err != nil {
		return Account{}, fmt.Errorf("cannot update the account: %w", err)
	}
	out := toAccount(a)
	if out.URL == "" {
		out.URL = accountURL
	}
	return out, nil
}

// Revoke revokes a certificate with the account key. A certificate that is already
// revoked counts as revoked: golang.org/x/crypto/acme treats the alreadyRevoked problem
// as success and returns no error, so no special case is needed here.
func Revoke(ctx context.Context, r Registration, leafDER []byte) error {
	acct, err := Lookup(ctx, r)
	if err != nil {
		return err
	}
	c := r.client()
	c.KID = xacme.KeyID(acct.URL)
	if err := c.RevokeCert(ctx, nil, leafDER, xacme.CRLReasonUnspecified); err != nil {
		return fmt.Errorf("cannot revoke the certificate: %w", err)
	}
	return nil
}
