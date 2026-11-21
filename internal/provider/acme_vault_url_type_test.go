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
		{"https://xyz.vault.azure.net", "https://xyz.vault.azure.net", true},
		{"https://xyz.vault.azure.net", "https://xyz.vault.azure.net/", true},
		{"https://Xyz.Vault.Azure.NET/", "https://xyz.vault.azure.net", true},
		{"https://xyz.vault.azure.net", "https://uvw.vault.azure.net", false},
		{"https://xyz.vault.azure.net", "http://x.vault.azure.net", false},
		{"https://xyz.vault.azure.net/a", "https://xyz.vault.azure.net", false},
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
