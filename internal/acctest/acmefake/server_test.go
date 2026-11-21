package acmefake_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/co-native-ab/terraform-provider-conative/internal/acctest"
	"github.com/co-native-ab/terraform-provider-conative/internal/acctest/acmefake"
	"github.com/co-native-ab/terraform-provider-conative/internal/acctest/dnsstore"
)

func TestDirectoryNonceAndMalformedRequests(t *testing.T) {
	certs, err := acctest.NewCerts(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv, err := acmefake.Start(certs.Server, dnsstore.New())
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	client := certs.HTTPClient()

	resp, err := client.Get(srv.DirectoryURL())
	if err != nil {
		t.Fatal(err)
	}
	var dir struct {
		NewNonce, NewAccount, NewOrder, RevokeCert string
		Meta                                       struct{ TermsOfService string }
	}
	if err := json.NewDecoder(resp.Body).Decode(&dir); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if dir.NewNonce == "" || dir.NewAccount == "" || dir.NewOrder == "" || dir.RevokeCert == "" || dir.Meta.TermsOfService == "" {
		t.Errorf("incomplete directory: %+v", dir)
	}

	head, err := client.Head(dir.NewNonce)
	if err != nil {
		t.Fatal(err)
	}
	_ = head.Body.Close()
	if head.Header.Get("Replay-Nonce") == "" {
		t.Error("no Replay-Nonce on a nonce request")
	}

	mark := srv.Journal.Mark()
	post, err := client.Post(dir.NewAccount, "application/jose+json", strings.NewReader("not a JWS"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(post.Body)
	_ = post.Body.Close()
	if post.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "malformed") {
		t.Errorf("a request that is not a JWS: %d %s", post.StatusCode, body)
	}
	if len(srv.Journal.WritesSince(mark)) != 1 {
		t.Error("a malformed POST must be journaled as a write")
	}
}
