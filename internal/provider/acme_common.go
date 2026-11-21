package provider

import (
	"context"
	"fmt"

	"github.com/co-native-ab/terraform-provider-conative/internal/acme"
	"github.com/co-native-ab/terraform-provider-conative/internal/acme/issuer"
	"github.com/co-native-ab/terraform-provider-conative/internal/acme/keyvault"
)

// keyVault returns a Key Vault client for a vault URL, authenticated with the Key
// Vault token.
func (a *acmeAccess) keyVault(vaultURL string) (*keyvault.Client, error) {
	return keyvault.New(vaultURL, a.keyVaultToken, a.http)
}

// registration builds what the protocol needs for the account of a directory and a
// Key Vault key: a signer whose key never leaves the vault.
func (a *acmeAccess) registration(ctx context.Context, serverURL string, key acme.KeyRef) (issuer.Registration, error) {
	kv, err := a.keyVault(key.Vault)
	if err != nil {
		return issuer.Registration{}, err
	}
	signer, err := keyvault.NewSigner(ctx, kv, key.Name, key.Version)
	if err != nil {
		return issuer.Registration{}, fmt.Errorf("cannot use the account key: %w", err)
	}
	return issuer.Registration{ServerURL: serverURL, Signer: signer, HTTPClient: a.http, RetryBase: a.env.retryBase}, nil
}
