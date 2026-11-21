// Package keyvault is a small client for the parts of the Azure Key Vault REST API the
// ACME resources use: signing with a key, and creating, merging, reading and deleting
// certificates. It makes no decisions; those belong to internal/acme.
//
// The client never calls the secrets API, never exports a key and never reads or writes
// a certificate policy.
package keyvault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const apiVersion = "7.5"

// maxResponse bounds how much of a response is read.
const maxResponse = 8 << 20

// ErrNotFound is matched (with errors.Is) by an error for a 404 answer.
var ErrNotFound = errors.New("not found")

// APIError is an error answer of Key Vault. It carries the status, code and message
// only: never the request, its headers or the token.
type APIError struct {
	Status  int
	Code    string
	Message string
	// InnerCode is the code of the inner error, for example ObjectIsDeletedButRecoverable.
	InnerCode string
}

// DeletedButRecoverable reports whether Key Vault refused because the name belongs to a
// soft-deleted object that can only be recovered or purged.
func (e *APIError) DeletedButRecoverable() bool {
	return e.Status == http.StatusConflict &&
		(e.InnerCode == "ObjectIsDeletedButRecoverable" || strings.Contains(strings.ToLower(e.Message), "deleted but recoverable"))
}

func (e *APIError) Error() string {
	switch {
	case e.Code != "" && e.Message != "":
		return fmt.Sprintf("Key Vault answered %d %s: %s", e.Status, e.Code, e.Message)
	case e.Code != "":
		return fmt.Sprintf("Key Vault answered %d %s", e.Status, e.Code)
	}
	return fmt.Sprintf("Key Vault answered %d", e.Status)
}

// Is makes a 404 match ErrNotFound.
func (e *APIError) Is(target error) bool {
	return target == ErrNotFound && e.Status == http.StatusNotFound
}

// Client talks to one vault with one access token.
type Client struct {
	base  string
	token string
	http  *http.Client
}

// New returns a client for the vault at baseURL (https://host[:port]). The token is
// sent only to that host. A base URL that is not https is refused.
func New(baseURL, token string, hc *http.Client) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("the Key Vault URL must be an https URL")
	}
	if hc == nil {
		hc = http.DefaultClient
	}
	return &Client{base: "https://" + u.Host, token: token, http: hc}, nil
}

// do sends a request. pathTemplate is logged instead of the path, which carries names.
func (c *Client) do(ctx context.Context, method, path, pathTemplate string, body, out any) error {
	return c.doURL(ctx, method, c.base+path+"?api-version="+apiVersion, pathTemplate, body, out)
}

func (c *Client) doURL(ctx context.Context, method, target, pathTemplate string, body, out any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		// The URL error holds the URL, which carries no secret, but the cause is enough.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("cannot reach Key Vault: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	tflog.Debug(ctx, "key vault request", map[string]any{"method": method, "path": pathTemplate, "status": resp.StatusCode})
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return fmt.Errorf("cannot read the Key Vault answer: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return parseError(resp.StatusCode, data)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("cannot understand the Key Vault answer: %w", err)
		}
	}
	return nil
}

func parseError(status int, data []byte) error {
	var e struct {
		Error struct {
			Code       string `json:"code"`
			Message    string `json:"message"`
			InnerError struct {
				Code string `json:"code"`
			} `json:"innererror"`
		} `json:"error"`
	}
	_ = json.Unmarshal(data, &e)
	return &APIError{Status: status, Code: e.Error.Code, Message: e.Error.Message, InnerCode: e.Error.InnerError.Code}
}

// sameHost reports whether a link returned by the service stays on the vault's host.
func (c *Client) sameHost(link string) bool {
	return strings.HasPrefix(link, c.base+"/")
}
