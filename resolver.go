package letsdebug

import (
	"time"

	"github.com/miekg/dns"
)

// LookupResult is a resolver-agnostic representation of a DNS lookup result.
// It contains the parsed RRs (if available), Rcode and additional metadata such as
// DNSSEC bogus flags and diagnostic text.
type LookupResult struct {
	RRs      []dns.RR
	Rcode    int
	Bogus    bool
	WhyBogus string
	NxDomain bool
}

// Resolver is the interface that DNS resolver implementations must satisfy.
// Implementations should perform a lookup for the given name and type and
// return a LookupResult. The timeout parameter is a hint and must be respected
// by implementations where applicable.
type Resolver interface {
	Lookup(name string, rrType uint16, timeout time.Duration) (*LookupResult, error)
}

var (
	globalResolver Resolver
)

// SetResolver sets the Resolver used by package-level lookup functions.
func SetResolver(r Resolver) {
	globalResolver = r
}

// GetResolver returns the currently configured Resolver. If none is set, a
// default resolver will be used. The concrete default is provided by
// defaultResolver() implemented in the resolver implementation files.
func GetResolver() Resolver {
	if globalResolver == nil {
		// defaultResolver is implemented in resolver_stdlib.go
		globalResolver = defaultResolver()
	}
	return globalResolver
}
