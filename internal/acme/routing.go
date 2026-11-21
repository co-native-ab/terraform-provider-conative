package acme

import (
	"fmt"
	"strings"
)

// BlockKind is the DNS provider of a block.
type BlockKind string

// The DNS providers a certificate can use.
const (
	KindAzureDNS   BlockKind = "azure_dns"
	KindCloudflare BlockKind = "cloudflare"
)

// Block is one DNS block of a certificate: the zone that answers challenges and the
// names it answers for.
type Block struct {
	Kind         BlockKind
	Index        int
	Zone         string
	MatchDomains []string
}

// String names the block as it appears in the configuration, for example azure_dns[0].
func (b Block) String() string { return fmt.Sprintf("%s[%d]", b.Kind, b.Index) }

// ValidateBlocks checks the blocks of a certificate as a whole: there is at least one,
// every match_domains entry is a DNS name equal to or inside its block's zone, and no
// entry appears in two blocks.
func ValidateBlocks(blocks []Block) error {
	if len(blocks) == 0 {
		return fmt.Errorf("at least one azure_dns or cloudflare block is required")
	}
	owner := map[string]Block{}
	for _, b := range blocks {
		if err := ValidateMatchDomain(b.Zone); err != nil {
			return fmt.Errorf("%s zone: %w", b, err)
		}
		if len(b.MatchDomains) == 0 {
			return fmt.Errorf("%s: match_domains needs at least one entry", b)
		}
		for _, d := range b.MatchDomains {
			if err := ValidateMatchDomain(d); err != nil {
				return fmt.Errorf("%s match_domains: %w", b, err)
			}
			if !within(d, b.Zone) {
				return fmt.Errorf("%s: match_domains entry %q is not equal to or inside the zone %q", b, d, b.Zone)
			}
			if other, ok := owner[d]; ok {
				return fmt.Errorf("match_domains entry %q appears in %s and %s", d, other, b)
			}
			owner[d] = b
		}
	}
	return nil
}

// within reports whether name equals zone or ends in "."+zone.
func within(name, zone string) bool {
	return name == zone || strings.HasSuffix(name, "."+zone)
}

// Route assigns every identifier to the block with the longest matching match_domains
// entry. A name matches an entry when its base (without a leading "*.") equals the
// entry or ends in "."+entry. The blocks must have passed ValidateBlocks.
func Route(identifiers []string, blocks []Block) (map[string]Block, error) {
	if err := ValidateBlocks(blocks); err != nil {
		return nil, err
	}
	out := make(map[string]Block, len(identifiers))
	for _, id := range identifiers {
		base := Base(id)
		best, bestLen := -1, -1
		for i, b := range blocks {
			for _, d := range b.MatchDomains {
				if within(base, d) && len(d) > bestLen {
					best, bestLen = i, len(d)
				}
			}
		}
		if best < 0 {
			return nil, fmt.Errorf("%q is not covered by any match_domains entry", id)
		}
		out[id] = blocks[best]
	}
	return out, nil
}
