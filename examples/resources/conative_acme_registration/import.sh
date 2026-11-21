# The import ID is <server_url>|<account_key_id>. Quote it: it contains a pipe.
# Importing looks up the account for the key, which signs a request with the key.
terraform import conative_acme_registration.letsencrypt 'https://acme-v02.api.letsencrypt.org/directory|https://example.vault.azure.net/keys/acme-account/0123456789abcdef0123456789abcdef'
