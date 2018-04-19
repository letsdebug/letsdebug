package letsdebug

import (
	"strings"

	"github.com/miekg/dns"
	"github.com/miekg/unbound"
)

func lookup(name string, rrType uint16) ([]dns.RR, error) {
	ub := unbound.New()
	defer ub.Destroy()

	result, err := ub.Resolve(name, rrType, dns.ClassINET)
	if err != nil {
		return nil, err
	}

	return result.Rr, nil
}

func normalizeFqdn(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, ".")
	return strings.ToLower(name)
}
