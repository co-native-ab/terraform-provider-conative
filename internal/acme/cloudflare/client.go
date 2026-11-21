// Package cloudflare is a small client for the parts of the Cloudflare API the ACME
// resources use: finding a zone and creating and deleting TXT records. It makes no
// decisions; those belong to internal/acme.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const maxResponse = 4 << 20

// Error is an error answer of Cloudflare: the status and the codes and messages it
// reported. It never holds the token.
type Error struct {
	Status   int
	Messages []string
	// Codes are the Cloudflare error codes of the answer.
	Codes []int
}

// codeIdenticalRecord is the code of the answer to creating a record that already
// exists with the same type, name and content.
const codeIdenticalRecord = 81058

// HasCode reports whether the answer carried the error code.
func (e *Error) HasCode(code int) bool { return slices.Contains(e.Codes, code) }

func (e *Error) Error() string {
	if len(e.Messages) == 0 {
		return fmt.Sprintf("Cloudflare answered %d", e.Status)
	}
	return fmt.Sprintf("Cloudflare answered %d: %s", e.Status, strings.Join(e.Messages, "; "))
}

// Client talks to the Cloudflare API with one API token.
type Client struct {
	base  string
	token string
	http  *http.Client
}

// New returns a client for the API at baseURL (https only, including the /client/v4
// path). The token is sent only there.
func New(baseURL, token string, hc *http.Client) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("the Cloudflare URL must be an https URL")
	}
	if hc == nil {
		hc = http.DefaultClient
	}
	return &Client{base: strings.TrimRight(baseURL, "/"), token: token, http: hc}, nil
}

type envelope struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

func (c *Client) do(ctx context.Context, method, path, template string, body any) (json.RawMessage, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, fmt.Errorf("cannot reach Cloudflare: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	tflog.Debug(ctx, "cloudflare request", map[string]any{"method": method, "path": template, "status": resp.StatusCode})
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return nil, fmt.Errorf("cannot read the Cloudflare answer: %w", err)
	}
	var env envelope
	parseErr := json.Unmarshal(data, &env)
	if resp.StatusCode < 200 || resp.StatusCode > 299 || (parseErr == nil && !env.Success) {
		e := &Error{Status: resp.StatusCode}
		for _, x := range env.Errors {
			e.Messages = append(e.Messages, fmt.Sprintf("%d %s", x.Code, x.Message))
			e.Codes = append(e.Codes, x.Code)
		}
		return nil, e
	}
	if parseErr != nil {
		return nil, fmt.Errorf("cannot understand the Cloudflare answer: %w", parseErr)
	}
	return env.Result, nil
}

// FindZone returns the ID of the active zone with exactly this name.
func (c *Client) FindZone(ctx context.Context, name string) (string, error) {
	res, err := c.do(ctx, "GET", "/zones?name="+url.QueryEscape(name)+"&status=active", "/zones", nil)
	if err != nil {
		return "", err
	}
	var zones []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(res, &zones); err != nil {
		return "", fmt.Errorf("cannot understand the Cloudflare answer: %w", err)
	}
	switch len(zones) {
	case 0:
		return "", fmt.Errorf("the Cloudflare zone %q was not found or cannot be read with this token", name)
	case 1:
		return zones[0].ID, nil
	}
	return "", fmt.Errorf("the Cloudflare zone name %q is ambiguous: %d zones match", name, len(zones))
}

// CreateTXT creates a TXT record and returns its ID.
func (c *Client) CreateTXT(ctx context.Context, zoneID, fqdn, value string) (string, error) {
	res, err := c.do(ctx, "POST", "/zones/"+url.PathEscape(zoneID)+"/dns_records", "/zones/{zone}/dns_records",
		map[string]any{"type": "TXT", "name": fqdn, "content": value, "ttl": 60})
	if err != nil {
		return "", err
	}
	var rec struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(res, &rec); err != nil || rec.ID == "" {
		return "", errors.New("the Cloudflare answer has no ID for the new record")
	}
	return rec.ID, nil
}

// FindTXT returns the IDs of the TXT records with exactly this name and content.
func (c *Client) FindTXT(ctx context.Context, zoneID, fqdn, value string) ([]string, error) {
	q := url.Values{"type": {"TXT"}, "name": {fqdn}, "content": {value}}
	res, err := c.do(ctx, "GET", "/zones/"+url.PathEscape(zoneID)+"/dns_records?"+q.Encode(), "/zones/{zone}/dns_records", nil)
	if err != nil {
		return nil, err
	}
	var recs []struct {
		ID      string `json:"id"`
		Type    string `json:"type"`
		Name    string `json:"name"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal(res, &recs); err != nil {
		return nil, fmt.Errorf("cannot understand the Cloudflare answer: %w", err)
	}
	var ids []string
	for _, r := range recs {
		// The content of a TXT record may come back in quotes.
		if r.Type == "TXT" && strings.EqualFold(r.Name, fqdn) && strings.Trim(r.Content, `"`) == value {
			ids = append(ids, r.ID)
		}
	}
	return ids, nil
}

// DeleteRecord deletes a record by ID; a record that is already gone counts as removed.
func (c *Client) DeleteRecord(ctx context.Context, zoneID, id string) error {
	_, err := c.do(ctx, "DELETE", "/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(id), "/zones/{zone}/dns_records/{id}", nil)
	var ce *Error
	if errors.As(err, &ce) && ce.Status == http.StatusNotFound {
		return nil
	}
	return err
}

// ZonePublisher publishes challenge records into one zone and remembers the records it
// created, so that it removes exactly those.
type ZonePublisher struct {
	client *Client
	zone   string

	mu     sync.Mutex
	zoneID string
	// created maps fqdn + "\x00" + value to the ID of a record this publisher created.
	created map[string]string
	// uncertain holds the records whose creation failed in a way that does not say
	// whether Cloudflare stored them (a timeout or a server error after the commit).
	uncertain map[string]bool
}

// NewZonePublisher returns a publisher for one zone.
func NewZonePublisher(c *Client, zone string) *ZonePublisher {
	return &ZonePublisher{client: c, zone: zone, created: map[string]string{}, uncertain: map[string]bool{}}
}

// Zone returns the zone name.
func (p *ZonePublisher) Zone() string { return p.zone }

// Check looks the zone up, to prove it exists and is readable with the token.
func (p *ZonePublisher) Check(ctx context.Context) error {
	_, err := p.lookup(ctx)
	return err
}

func (p *ZonePublisher) lookup(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.zoneID != "" {
		return p.zoneID, nil
	}
	id, err := p.client.FindZone(ctx, p.zone)
	if err != nil {
		return "", err
	}
	p.zoneID = id
	return id, nil
}

// writeHint is added to a 403 on a write: the token can read the zone but not change it.
const writeHint = "the token needs DNS Edit permission on the zone; a read-only token can plan but not apply"

// unknownOutcome reports whether a failed create may still have been committed: the
// request never got a complete answer, or the server failed.
func unknownOutcome(err error) bool {
	var ce *Error
	if errors.As(err, &ce) {
		return ce.Status >= 500
	}
	return true
}

// Publish creates one TXT record per value. A record with the same name and content that
// already exists (another order for the same name published it) is used as it is: it is
// not owned by this publisher and is never deleted by it.
func (p *ZonePublisher) Publish(ctx context.Context, fqdn string, values []string) error {
	zoneID, err := p.lookup(ctx)
	if err != nil {
		return err
	}
	for _, v := range values {
		key := fqdn + "\x00" + v
		id, err := p.client.CreateTXT(ctx, zoneID, fqdn, v)
		var ce *Error
		switch {
		case err == nil:
			p.mu.Lock()
			p.created[key] = id
			p.mu.Unlock()
		case errors.As(err, &ce) && ce.HasCode(codeIdenticalRecord):
			ids, ferr := p.client.FindTXT(ctx, zoneID, fqdn, v)
			if ferr != nil {
				return fmt.Errorf("cannot create the record %s: an identical record exists but cannot be read: %w", fqdn, ferr)
			}
			if len(ids) == 0 {
				return fmt.Errorf("cannot create the record %s: %w", fqdn, err)
			}
			tflog.Debug(ctx, "an identical challenge record already exists and is used as it is", map[string]any{"name": fqdn})
		default:
			if unknownOutcome(err) {
				p.mu.Lock()
				p.uncertain[key] = true
				p.mu.Unlock()
			}
			if errors.As(err, &ce) && ce.Status == http.StatusForbidden {
				return fmt.Errorf("cannot create the record %s: %w (%s)", fqdn, err, writeHint)
			}
			return fmt.Errorf("cannot create the record %s: %w", fqdn, err)
		}
	}
	return nil
}

// Remove deletes the records this publisher created for the values. For a value whose
// creation had an unknown outcome there is no ID: the records with that name and
// content are looked up and deleted.
func (p *ZonePublisher) Remove(ctx context.Context, fqdn string, values []string) error {
	p.mu.Lock()
	zoneID := p.zoneID
	p.mu.Unlock()
	var errs []error
	for _, v := range values {
		key := fqdn + "\x00" + v
		p.mu.Lock()
		id, ok := p.created[key]
		unsure := p.uncertain[key]
		p.mu.Unlock()
		var ids []string
		switch {
		case ok:
			ids = []string{id}
		case unsure:
			found, err := p.client.FindTXT(ctx, zoneID, fqdn, v)
			if err != nil {
				errs = append(errs, fmt.Errorf("cannot look for the record %s: %w", fqdn, err))
				continue
			}
			ids = found
		default:
			continue
		}
		failed := false
		for _, rid := range ids {
			if err := p.client.DeleteRecord(ctx, zoneID, rid); err != nil {
				errs = append(errs, fmt.Errorf("cannot delete the record %s: %w", fqdn, err))
				failed = true
			}
		}
		if !failed {
			p.mu.Lock()
			delete(p.created, key)
			delete(p.uncertain, key)
			p.mu.Unlock()
		}
	}
	return errors.Join(errs...)
}
