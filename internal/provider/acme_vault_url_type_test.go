package provider

import (
	"context"
	"testing"
)

func TestVaultURLSemanticEquals(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"https://x.vault.azure.net", "https://x.vault.azure.net", true},
		{"https://x.vault.azure.net", "https://x.vault.azure.net/", true},
		{"https://X.Vault.Azure.NET/", "https://x.vault.azure.net", true},
		{"https://x.vault.azure.net", "https://y.vault.azure.net", false},
		{"https://x.vault.azure.net", "http://x.vault.azure.net", false},
		{"https://x.vault.azure.net/a", "https://x.vault.azure.net", false},
	} {
		got, diags := newVaultURL(c.a).StringSemanticEquals(ctx, newVaultURL(c.b))
		if diags.HasError() || got != c.want {
			t.Errorf("%q vs %q: got %v, want %v", c.a, c.b, got, c.want)
		}
		back, _ := newVaultURL(c.b).StringSemanticEquals(ctx, newVaultURL(c.a))
		if back != got {
			t.Errorf("%q vs %q: not symmetric", c.a, c.b)
		}
	}
}
