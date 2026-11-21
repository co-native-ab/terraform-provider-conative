// Package acme holds the decisions behind the ACME resources as pure functions:
// validating names and identifiers, routing names to DNS zones, building record names,
// parsing and formatting Key Vault identifiers, mapping key types, deciding when a
// certificate must be ordered, inspecting certificates and building the Key Vault
// certificate policy.
//
// Nothing here uses the network, the file system, the environment or the clock; callers
// pass the current time in. Lint rules enforce it. Talking to services lives in the
// subpackages, which make no decisions.
package acme
