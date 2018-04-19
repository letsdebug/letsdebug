package letsdebug

import (
	"errors"
	"fmt"
	"net"

	"github.com/miekg/dns"
)

// ValidationMethod represents an ACME validation method
type ValidationMethod string

const (
	// HTTP01 represents the ACME http-01 validation method.
	HTTP01 ValidationMethod = "http-01"
)

var (
	errNotApplicable = errors.New("Checker not applicable for this domain and method")
	checkers         []checker
)

func init() {
	checkers = []checker{}
	checkers = append(checkers, aaaaInaccessibilityChecker{})
}

type checker interface {
	Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error)
}

// aaaaInaccessibilityChecker checks whether a domain is advertising AAAA records
// that are not accessible over HTTP/port 80.
type aaaaInaccessibilityChecker struct {
}

func (c aaaaInaccessibilityChecker) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	if method != HTTP01 {
		return nil, errNotApplicable
	}

	probs := []Problem{}

	rrs, err := ctx.Lookup(domain, dns.TypeAAAA)
	if err != nil {
		probs = append(probs, internalProblem(fmt.Sprintf("Couldn't look up AAAA record: %v", err)))
		return probs, nil
	}

	ips := []net.IP{}

	for _, rr := range rrs {
		aaaa, ok := rr.(*dns.AAAA)
		if !ok {
			continue
		}
		ips = append(ips, aaaa.AAAA)
	}

	for _, ip := range ips {
		if err := checkHTTP(domain, ip); err != nil {
			probs = append(probs, aaaaNotWorking(domain, ip.String(), err))
		}
	}

	return probs, nil
}
