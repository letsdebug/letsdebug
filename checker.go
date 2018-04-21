package letsdebug

import (
	"errors"
)

// ValidationMethod represents an ACME validation method
type ValidationMethod string

const (
	HTTP01   ValidationMethod = "http-01"    // HTTP01 represents the ACME http-01 validation method.
	DNS01    ValidationMethod = "dns-01"     // DNS01 represents the ACME dns-01 validation method.
	TLSSNI01 ValidationMethod = "tls-sni-01" // TLSSNI01 represents the ACME tls-sni-01 validation method.
	TLSSNI02 ValidationMethod = "tls-sni-02" // TLSSNI02 represents the ACME tls-sni-02 validation method.
)

var (
	ValidMethods     = map[ValidationMethod]bool{HTTP01: true, DNS01: true, TLSSNI01: true, TLSSNI02: true}
	errNotApplicable = errors.New("Checker not applicable for this domain and method")
	checkers         []checker
)

func init() {
	checkers = []checker{
		// show stopping checkers
		tlssni0102DisabledChecker{},
		wildcardDns01OnlyChecker{},
		caaChecker{},

		// others
		dnsAChecker{},
		httpAccessibilityChecker{},
	}
}

type checker interface {
	Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error)
}
