package keyvault

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/co-native-ab/terraform-provider-conative/internal/acme"
)

// Pending is a certificate operation that waits for a certificate to be merged.
type Pending struct {
	Issuer string
	CSR    []byte // DER
	Status string
}

type pendingJSON struct {
	Issuer struct {
		Name string `json:"name"`
	} `json:"issuer"`
	CSR    string `json:"csr"`
	Status string `json:"status"`
}

func (p pendingJSON) decode() (Pending, error) {
	out := Pending{Issuer: p.Issuer.Name, Status: p.Status}
	if p.CSR != "" {
		csr, err := base64.StdEncoding.DecodeString(p.CSR)
		if err != nil {
			return Pending{}, fmt.Errorf("Key Vault returned a signing request that is not base64: %w", err)
		}
		out.CSR = csr
	}
	return out, nil
}

// Bundle is a certificate version.
type Bundle struct {
	ID      string
	Version string
	// Cer is the leaf certificate, DER; empty for a version that is still pending.
	Cer     []byte
	Created time.Time
	Expires time.Time
	Enabled bool
	// Issued is true when the version has a certificate (it is not a pending version).
	Issued bool
}

type bundleJSON struct {
	ID         string `json:"id"`
	Cer        string `json:"cer"`
	X5T        string `json:"x5t"`
	Attributes struct {
		Enabled *bool `json:"enabled"`
		Created int64 `json:"created"`
		Exp     int64 `json:"exp"`
	} `json:"attributes"`
}

func (b bundleJSON) decode() (Bundle, error) {
	out := Bundle{ID: b.ID, Version: versionOf(b.ID), Enabled: b.Attributes.Enabled == nil || *b.Attributes.Enabled, Issued: b.Cer != "" || b.X5T != ""}
	if b.Cer != "" {
		der, err := base64.StdEncoding.DecodeString(b.Cer)
		if err != nil {
			return Bundle{}, fmt.Errorf("Key Vault returned a certificate that is not base64: %w", err)
		}
		out.Cer = der
	}
	if b.Attributes.Created != 0 {
		out.Created = time.Unix(b.Attributes.Created, 0).UTC()
	}
	if b.Attributes.Exp != 0 {
		out.Expires = time.Unix(b.Attributes.Exp, 0).UTC()
	}
	return out, nil
}

// versionOf returns the last path segment of a certificate ID, or "" for an ID without
// a version.
func versionOf(id string) string {
	u, err := url.Parse(id)
	if err != nil {
		return ""
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) == 3 && parts[0] == "certificates" && parts[2] != "pending" {
		return parts[2]
	}
	return ""
}

func certPath(name string) string { return "/certificates/" + url.PathEscape(name) }

// CreateCertificate posts a create request: Key Vault adds a pending version under the
// given policy, generates the key and returns the signing request.
func (c *Client) CreateCertificate(ctx context.Context, name string, body acme.Policy) (Pending, error) {
	var out pendingJSON
	if err := c.do(ctx, "POST", certPath(name)+"/create", "/certificates/{name}/create", body, &out); err != nil {
		return Pending{}, err
	}
	return out.decode()
}

// GetPending reads the pending operation of a certificate; ErrNotFound when there is none.
func (c *Client) GetPending(ctx context.Context, name string) (Pending, error) {
	var out pendingJSON
	if err := c.do(ctx, "GET", certPath(name)+"/pending", "/certificates/{name}/pending", nil, &out); err != nil {
		return Pending{}, err
	}
	return out.decode()
}

// DeletePending cancels the pending operation of a certificate.
func (c *Client) DeletePending(ctx context.Context, name string) error {
	return c.do(ctx, "DELETE", certPath(name)+"/pending", "/certificates/{name}/pending", nil, nil)
}

// Merge completes the pending operation with an issued chain, leaf first.
func (c *Client) Merge(ctx context.Context, name string, chain [][]byte) (Bundle, error) {
	x5c := make([]string, len(chain))
	for i, d := range chain {
		x5c[i] = base64.StdEncoding.EncodeToString(d)
	}
	var out bundleJSON
	if err := c.do(ctx, "POST", certPath(name)+"/pending/merge", "/certificates/{name}/pending/merge", map[string]any{"x5c": x5c}, &out); err != nil {
		return Bundle{}, err
	}
	return out.decode()
}

// GetCertificate reads the latest version of a certificate.
func (c *Client) GetCertificate(ctx context.Context, name string) (Bundle, error) {
	var out bundleJSON
	if err := c.do(ctx, "GET", certPath(name), "/certificates/{name}", nil, &out); err != nil {
		return Bundle{}, err
	}
	return out.decode()
}

// GetCertificateVersion reads one version of a certificate.
func (c *Client) GetCertificateVersion(ctx context.Context, name, version string) (Bundle, error) {
	var out bundleJSON
	if err := c.do(ctx, "GET", certPath(name)+"/"+url.PathEscape(version), "/certificates/{name}/{version}", nil, &out); err != nil {
		return Bundle{}, err
	}
	return out.decode()
}

// ListVersions lists the versions of a certificate, following the service's paging.
func (c *Client) ListVersions(ctx context.Context, name string) ([]Bundle, error) {
	var all []Bundle
	target := c.base + certPath(name) + "/versions?api-version=" + apiVersion
	for page := 0; target != ""; page++ {
		if page > 100 {
			return nil, fmt.Errorf("Key Vault returned too many pages of versions")
		}
		var out struct {
			Value    []bundleJSON `json:"value"`
			NextLink string       `json:"nextLink"`
		}
		if err := c.doURL(ctx, "GET", target, "/certificates/{name}/versions", nil, &out); err != nil {
			return nil, err
		}
		for _, v := range out.Value {
			b, err := v.decode()
			if err != nil {
				return nil, err
			}
			all = append(all, b)
		}
		target = ""
		if out.NextLink != "" {
			if !c.sameHost(out.NextLink) {
				return nil, fmt.Errorf("Key Vault returned a paging link to another host")
			}
			target = out.NextLink
		}
	}
	return all, nil
}

// DeleteCertificate soft-deletes a certificate. A certificate that is already gone is
// not an error.
func (c *Client) DeleteCertificate(ctx context.Context, name string) error {
	err := c.do(ctx, "DELETE", certPath(name), "/certificates/{name}", nil, nil)
	if isNotFound(err) {
		return nil
	}
	return err
}

func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrNotFound)
}
