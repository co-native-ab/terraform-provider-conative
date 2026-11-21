// Package azuredns is a small client for the parts of the Azure Resource Manager DNS API
// the ACME resources use: reading a zone and adding or removing TXT values in a record
// set. It makes no decisions; those belong to internal/acme.
package azuredns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/co-native-ab/terraform-provider-conative/internal/acme"
)

const (
	apiVersion  = "2018-05-01"
	defaultTTL  = 60
	maxAttempts = 3
	maxResponse = 4 << 20
)

// ErrNotFound is matched (with errors.Is) by an error for a 404 answer.
var ErrNotFound = errors.New("not found")

// APIError is an error answer of Resource Manager: status, code and message only.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("Azure DNS answered %d %s: %s", e.Status, e.Code, e.Message)
	}
	return fmt.Sprintf("Azure DNS answered %d", e.Status)
}

// Is makes a 404 match ErrNotFound.
func (e *APIError) Is(target error) bool {
	return target == ErrNotFound && e.Status == http.StatusNotFound
}

// Client talks to Resource Manager with one access token.
type Client struct {
	base  string
	token string
	http  *http.Client
}

// New returns a client for the Resource Manager endpoint at baseURL (https only).
func New(baseURL, token string, hc *http.Client) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("the Resource Manager URL must be an https URL")
	}
	if hc == nil {
		hc = http.DefaultClient
	}
	return &Client{base: "https://" + u.Host, token: token, http: hc}, nil
}

// Zone is a DNS zone as far as the provider needs it.
type Zone struct {
	Name        string
	NameServers []string
}

func zonePath(sub, rg, zone string) string {
	return "/subscriptions/" + url.PathEscape(sub) + "/resourceGroups/" + url.PathEscape(rg) +
		"/providers/Microsoft.Network/dnsZones/" + url.PathEscape(zone)
}

type response struct {
	status int
	etag   string
	body   []byte
}

func (c *Client) do(ctx context.Context, method, path, template string, headers map[string]string, body any) (response, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return response{}, err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path+"?api-version="+apiVersion, reader)
	if err != nil {
		return response{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return response{}, fmt.Errorf("cannot reach Azure DNS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	tflog.Debug(ctx, "azure dns request", map[string]any{"method": method, "path": template, "status": resp.StatusCode})
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return response{}, fmt.Errorf("cannot read the Azure DNS answer: %w", err)
	}
	out := response{status: resp.StatusCode, etag: resp.Header.Get("ETag"), body: data}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e struct {
			Error struct{ Code, Message string } `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		return out, &APIError{Status: resp.StatusCode, Code: e.Error.Code, Message: e.Error.Message}
	}
	return out, nil
}

// GetZone reads a zone; ErrNotFound when it does not exist.
func (c *Client) GetZone(ctx context.Context, sub, rg, zone string) (Zone, error) {
	r, err := c.do(ctx, "GET", zonePath(sub, rg, zone), "/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/dnsZones/{zone}", nil, nil)
	if err != nil {
		return Zone{}, err
	}
	var out struct {
		Name       string `json:"name"`
		Properties struct {
			NameServers []string `json:"nameServers"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(r.body, &out); err != nil {
		return Zone{}, fmt.Errorf("cannot understand the Azure DNS answer: %w", err)
	}
	return Zone{Name: out.Name, NameServers: out.Properties.NameServers}, nil
}

type txtRecord struct {
	Value []string `json:"value"`
}

type recordSet struct {
	Etag       string `json:"etag,omitempty"`
	Properties struct {
		TTL        int               `json:"TTL"`
		Metadata   map[string]string `json:"metadata,omitempty"`
		TXTRecords []txtRecord       `json:"TXTRecords"`
	} `json:"properties"`
}

func (s recordSet) values() [][]string {
	out := make([][]string, len(s.Properties.TXTRecords))
	for i, r := range s.Properties.TXTRecords {
		out[i] = r.Value
	}
	return out
}

func (s *recordSet) setValues(v [][]string) {
	s.Properties.TXTRecords = make([]txtRecord, len(v))
	for i, r := range v {
		s.Properties.TXTRecords[i] = txtRecord{Value: r}
	}
}

func txtPath(sub, rg, zone, name string) string {
	return zonePath(sub, rg, zone) + "/TXT/" + url.PathEscape(name)
}

const txtTemplate = "/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/dnsZones/{zone}/TXT/{name}"

// getSet reads a TXT record set; found is false when it does not exist.
func (c *Client) getSet(ctx context.Context, sub, rg, zone, name string) (set recordSet, etag string, found bool, err error) {
	r, err := c.do(ctx, "GET", txtPath(sub, rg, zone, name), txtTemplate, nil, nil)
	if errors.Is(err, ErrNotFound) {
		return recordSet{}, "", false, nil
	}
	if err != nil {
		return recordSet{}, "", false, err
	}
	if err := json.Unmarshal(r.body, &set); err != nil {
		return recordSet{}, "", false, fmt.Errorf("cannot understand the Azure DNS answer: %w", err)
	}
	etag = r.etag
	if etag == "" {
		etag = set.Etag
	}
	return set, etag, true, nil
}

func isPreconditionFailed(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusPreconditionFailed
}

// Add adds TXT values to the record set name of a zone, keeping every value that is
// already there. The write is guarded by the set's ETag; when it changed in the
// meantime the set is read again, at most three times.
func (c *Client) Add(ctx context.Context, sub, rg, zone, name string, values []string) error {
	var last error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		set, etag, found, err := c.getSet(ctx, sub, rg, zone, name)
		if err != nil {
			return err
		}
		headers := map[string]string{"If-None-Match": "*"}
		if found {
			headers = map[string]string{"If-Match": etag}
		} else {
			set.Properties.TTL = defaultTTL
		}
		set.setValues(acme.AddValues(set.values(), values))
		set.Etag = ""
		_, err = c.do(ctx, "PUT", txtPath(sub, rg, zone, name), txtTemplate, headers, set)
		if err == nil {
			return nil
		}
		if !isPreconditionFailed(err) {
			return err
		}
		last = err
	}
	return fmt.Errorf("the record set %s changed too often while it was updated: %w", name, last)
}

// Remove removes the given TXT values from the record set, keeping every other value.
// A set left empty is deleted.
func (c *Client) Remove(ctx context.Context, sub, rg, zone, name string, values []string) error {
	var last error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		set, etag, found, err := c.getSet(ctx, sub, rg, zone, name)
		if err != nil {
			return err
		}
		if !found {
			return nil
		}
		existing := set.values()
		remaining := acme.RemoveValues(existing, values)
		if len(remaining) == len(existing) {
			return nil
		}
		headers := map[string]string{"If-Match": etag}
		if len(remaining) == 0 {
			_, err = c.do(ctx, "DELETE", txtPath(sub, rg, zone, name), txtTemplate, headers, nil)
			if errors.Is(err, ErrNotFound) {
				return nil
			}
		} else {
			set.setValues(remaining)
			set.Etag = ""
			_, err = c.do(ctx, "PUT", txtPath(sub, rg, zone, name), txtTemplate, headers, set)
		}
		if err == nil {
			return nil
		}
		if !isPreconditionFailed(err) {
			return err
		}
		last = err
	}
	return fmt.Errorf("the record set %s changed too often while it was updated: %w", name, last)
}

// ZonePublisher publishes challenge records into one zone.
type ZonePublisher struct {
	client *Client
	sub    string
	rg     string
	zone   string
}

// NewZonePublisher returns a publisher for one zone.
func NewZonePublisher(c *Client, sub, rg, zone string) *ZonePublisher {
	return &ZonePublisher{client: c, sub: sub, rg: rg, zone: zone}
}

// Check reads the zone, to prove it exists and is readable.
func (p *ZonePublisher) Check(ctx context.Context) error {
	if _, err := p.client.GetZone(ctx, p.sub, p.rg, p.zone); err != nil {
		return fmt.Errorf("the Azure DNS zone %q: %w", p.zone, err)
	}
	return nil
}

// Zone returns the zone name.
func (p *ZonePublisher) Zone() string { return p.zone }

// Publish adds the values to the TXT record set of fqdn.
func (p *ZonePublisher) Publish(ctx context.Context, fqdn string, values []string) error {
	rel, err := acme.AzureRelativeName(fqdn, p.zone)
	if err != nil {
		return err
	}
	return p.client.Add(ctx, p.sub, p.rg, p.zone, rel, values)
}

// Remove removes the values from the TXT record set of fqdn.
func (p *ZonePublisher) Remove(ctx context.Context, fqdn string, values []string) error {
	rel, err := acme.AzureRelativeName(fqdn, p.zone)
	if err != nil {
		return err
	}
	return p.client.Remove(ctx, p.sub, p.rg, p.zone, rel, values)
}
