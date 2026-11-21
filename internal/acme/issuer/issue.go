package issuer

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	xacme "golang.org/x/crypto/acme"

	"github.com/co-native-ab/terraform-provider-conative/internal/acme"
	"github.com/co-native-ab/terraform-provider-conative/internal/acme/dnscheck"
	"github.com/co-native-ab/terraform-provider-conative/internal/acme/keyvault"
)

// DNSPublisher writes and removes challenge TXT values in one DNS zone.
type DNSPublisher interface {
	Zone() string
	Publish(ctx context.Context, fqdn string, values []string) error
	Remove(ctx context.Context, fqdn string, values []string) error
}

// Order is everything an order needs.
type Order struct {
	Registration Registration
	Vault        *keyvault.Client
	// Certificate is the Key Vault certificate name.
	Certificate string
	CommonName  string
	// Identifiers are the names to certify, common name first.
	Identifiers []string
	KeyType     string
	// Creating is true when the Key Vault certificate must not exist yet.
	Creating bool
	// ImportID is the ID a user imports an existing certificate with; it is named when
	// Creating finds one.
	ImportID string
	// Routes assigns every identifier to a block; Publishers is keyed by Block.String().
	Routes     map[string]acme.Block
	Publishers map[string]DNSPublisher
	Checker    dnscheck.Checker
	// WaitTimeout bounds the wait for the authorizations and for the order (default
	// five minutes each).
	WaitTimeout time.Duration
}

// Result is a completed order.
type Result struct {
	Bundle keyvault.Bundle
	Info   acme.Info
}

// published is a record the order wrote and must remove.
type published struct {
	publisher DNSPublisher
	fqdn      string
	values    []string
}

// Issue runs an order: it prepares Key Vault, creates a certificate version whose key
// and signing request Key Vault generates, proves control of every name through DNS-01
// challenges, finalizes with Key Vault's signing request and merges the issued chain
// back. Whatever happens, the TXT values it wrote are removed and a pending operation it
// created is deleted before it returns.
func Issue(ctx context.Context, o Order) (res Result, err error) {
	if o.WaitTimeout <= 0 {
		o.WaitTimeout = 5 * time.Minute
	}
	name := o.Certificate

	if err := o.prepareKeyVault(ctx); err != nil {
		return Result{}, err
	}
	acct, err := Lookup(ctx, o.Registration)
	if err != nil {
		if errors.Is(err, ErrNoAccount) {
			return Result{}, errors.New("the certificate authority has no account for the registration's key; apply the conative_acme_registration first")
		}
		return Result{}, err
	}
	client := o.Registration.client()
	client.KID = xacme.KeyID(acct.URL)

	policy, err := acme.CreatePolicy(o.CommonName, o.Identifiers, o.KeyType)
	if err != nil {
		return Result{}, err
	}
	pending, err := o.Vault.CreateCertificate(ctx, name, policy)
	if err != nil {
		return Result{}, fmt.Errorf("cannot create the Key Vault certificate %q: %w", name, err)
	}

	var written []published
	merged := false
	defer func() {
		if err == nil {
			return
		}
		// Clean up even when the operation was cancelled.
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
		defer cancel()
		if rerr := removeAll(cctx, &written); rerr != nil {
			err = errors.Join(err, rerr)
		}
		if !merged {
			if derr := o.Vault.DeletePending(cctx, name); derr != nil && !errors.Is(derr, keyvault.ErrNotFound) {
				err = errors.Join(err, fmt.Errorf("cannot delete the pending Key Vault operation of %q: %w", name, derr))
			}
		}
	}()

	csr := pending.CSR
	if len(csr) == 0 {
		p, gerr := o.Vault.GetPending(ctx, name)
		if gerr != nil {
			return Result{}, fmt.Errorf("cannot read the signing request of %q: %w", name, gerr)
		}
		csr = p.CSR
	}
	if len(csr) == 0 {
		return Result{}, fmt.Errorf("the vault returned no signing request for %q", name)
	}

	ids := make([]xacme.AuthzID, len(o.Identifiers))
	for i, id := range o.Identifiers {
		ids[i] = xacme.AuthzID{Type: "dns", Value: id}
	}
	order, err := client.AuthorizeOrder(ctx, ids)
	if err != nil {
		return Result{}, fmt.Errorf("cannot create the order: %w", err)
	}

	type pendingChallenge struct {
		chal  *xacme.Challenge
		authz string
		name  string
	}
	var challenges []pendingChallenge
	values := map[string]string{} // identifier -> challenge value
	for _, url := range order.AuthzURLs {
		authz, gerr := client.GetAuthorization(ctx, url)
		if gerr != nil {
			return Result{}, fmt.Errorf("cannot read an authorization: %w", gerr)
		}
		identifier := authz.Identifier.Value
		if authz.Wildcard {
			identifier = "*." + identifier
		}
		if authz.Status == xacme.StatusValid {
			continue
		}
		var dns *xacme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "dns-01" {
				dns = c
			}
		}
		if dns == nil {
			return Result{}, fmt.Errorf("the certificate authority offers no dns-01 challenge for %q", identifier)
		}
		v, verr := client.DNS01ChallengeRecord(dns.Token)
		if verr != nil {
			return Result{}, verr
		}
		values[identifier] = v
		challenges = append(challenges, pendingChallenge{chal: dns, authz: url, name: identifier})
	}

	// Publish, grouped by record name and routed by the identifier's base.
	records := acme.ChallengeRecords(values)
	fqdns := make([]string, 0, len(records))
	for fqdn := range records {
		fqdns = append(fqdns, fqdn)
	}
	slices.Sort(fqdns)
	owner := map[string]DNSPublisher{}
	for identifier := range values {
		block, ok := o.Routes[identifier]
		if !ok {
			return Result{}, fmt.Errorf("%q is not routed to a DNS block", identifier)
		}
		pub, ok := o.Publishers[block.String()]
		if !ok {
			return Result{}, fmt.Errorf("no publisher for %s", block)
		}
		owner[acme.ChallengeFQDN(identifier)] = pub
	}
	for _, fqdn := range fqdns {
		pub := owner[fqdn]
		// Record before publishing: a failure half way still removes what was written.
		written = append(written, published{publisher: pub, fqdn: fqdn, values: records[fqdn]})
		if perr := pub.Publish(ctx, fqdn, records[fqdn]); perr != nil {
			return Result{}, fmt.Errorf("cannot publish the challenge record %s: %w", fqdn, perr)
		}
	}
	for _, fqdn := range fqdns {
		if cerr := o.Checker.Wait(ctx, fqdn, owner[fqdn].Zone(), records[fqdn]); cerr != nil {
			return Result{}, fmt.Errorf("the challenge record %s did not become visible: %w", fqdn, cerr)
		}
	}

	for _, c := range challenges {
		if _, aerr := client.Accept(ctx, c.chal); aerr != nil {
			return Result{}, fmt.Errorf("cannot ask the certificate authority to validate %q: %w", c.name, aerr)
		}
	}
	for _, c := range challenges {
		wctx, cancel := context.WithTimeout(ctx, o.WaitTimeout)
		_, werr := client.WaitAuthorization(wctx, c.authz)
		cancel()
		if werr != nil {
			return Result{}, fmt.Errorf("the certificate authority did not validate %q: %w", c.name, werr)
		}
	}

	// The records are no longer needed. Remove them before finalizing, so that a failure
	// to clean up stops the order instead of leaving them behind.
	if rerr := removeAll(ctx, &written); rerr != nil {
		written = nil // the error names the records that are left; do not repeat it
		return Result{}, rerr
	}

	wctx, cancel := context.WithTimeout(ctx, o.WaitTimeout)
	ready, werr := client.WaitOrder(wctx, order.URI)
	cancel()
	if werr != nil {
		return Result{}, fmt.Errorf("the order did not become ready: %w", werr)
	}
	chain, _, ferr := client.CreateOrderCert(ctx, ready.FinalizeURL, csr, true)
	if ferr != nil {
		return Result{}, fmt.Errorf("cannot finalize the order: %w", ferr)
	}
	if verr := acme.VerifyChain(chain, csr, o.Identifiers); verr != nil {
		return Result{}, fmt.Errorf("the issued certificate was refused: %w", verr)
	}
	bundle, merr := o.Vault.Merge(ctx, name, chain)
	if merr != nil {
		return Result{}, fmt.Errorf("cannot merge the issued certificate into %q (it was issued, but its key is discarded with the pending operation): %w", name, merr)
	}
	merged = true
	info, ierr := acme.Inspect(bundle.Cer)
	if ierr != nil {
		// The merge succeeded; nothing can be undone, so say what is wrong.
		return Result{}, fmt.Errorf("the merged certificate cannot be read: %w", ierr)
	}
	return Result{Bundle: bundle, Info: info}, nil
}

// prepareKeyVault checks the certificate in Key Vault and deletes a leftover pending
// operation of issuer Unknown.
func (o Order) prepareKeyVault(ctx context.Context) error {
	del, err := CheckVault(ctx, o.Vault, o.Certificate, o.Creating, o.ImportID)
	if err != nil {
		return err
	}
	if del {
		if err := o.Vault.DeletePending(ctx, o.Certificate); err != nil {
			return fmt.Errorf("cannot delete the leftover pending operation of %q: %w", o.Certificate, err)
		}
	}
	return nil
}

// CheckVault reads the versions and the pending operation of a Key Vault certificate and
// applies the decision of acme.PrepareKeyVault. It only reads. It reports whether a
// leftover pending operation has to be deleted before an order.
func CheckVault(ctx context.Context, vault *keyvault.Client, name string, creating bool, importID string) (deletePending bool, err error) {
	var state acme.VaultState
	versions, err := vault.ListVersions(ctx, name)
	if err != nil && !errors.Is(err, keyvault.ErrNotFound) {
		return false, fmt.Errorf("cannot read the versions of the Key Vault certificate %q: %w", name, err)
	}
	for _, v := range versions {
		if v.Issued {
			state.HasIssuedVersion = true
		}
	}
	p, err := vault.GetPending(ctx, name)
	switch {
	case err == nil:
		state.HasPending, state.PendingIssuer = true, p.Issuer
	case !errors.Is(err, keyvault.ErrNotFound):
		return false, fmt.Errorf("cannot read the pending operation of the Key Vault certificate %q: %w", name, err)
	}
	del, err := acme.PrepareKeyVault(state, creating, importID)
	if err != nil {
		return false, fmt.Errorf("%q: %w", name, err)
	}
	return del, nil
}

// removeAll removes every record written so far and forgets the ones it removed. The
// error names the records that are left.
func removeAll(ctx context.Context, written *[]published) error {
	var errs []error
	var left []published
	for _, w := range *written {
		if err := w.publisher.Remove(ctx, w.fqdn, w.values); err != nil {
			errs = append(errs, fmt.Errorf("the challenge record %s may still exist and has to be removed by hand: %w", w.fqdn, err))
			left = append(left, w)
		}
	}
	*written = left
	if len(errs) == 0 {
		return nil
	}
	names := make([]string, len(left))
	for i, l := range left {
		names[i] = l.fqdn
	}
	return fmt.Errorf("cannot remove the challenge records (%s): %w", strings.Join(names, ", "), errors.Join(errs...))
}
