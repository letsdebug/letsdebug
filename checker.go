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
	checkers = append(checkers, reservedAddressChecker{})
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
		probs = append(probs, dnsLookupFailed(domain, "AAAA", err))
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
		// Reserved addresses are handled by reservedAddressChecker
		// so we ignore them here
		if isAddressReserved(ip) {
			continue
		}
		if err := checkHTTP(domain, ip); err != nil {
			probs = append(probs, aaaaNotWorking(domain, ip.String(), err))
		}
	}

	return probs, nil
}

// reservedAddressChecker checks whether a domain has any IANA-reserved addresses.
// It also checks if no A or AAAA record can be found for the domain.
type reservedAddressChecker struct {
}

func (c reservedAddressChecker) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	if method != HTTP01 {
		return nil, errNotApplicable
	}

	probs := []Problem{}
	var recordCount int

	aRRs, err := ctx.Lookup(domain, dns.TypeA)
	if err != nil {
		probs = append(probs, dnsLookupFailed(domain, "A", err))
	} else {
		for _, rr := range aRRs {
			a, ok := rr.(*dns.A)
			if !ok {
				continue
			}
			recordCount++
			if isAddressReserved(a.A) {
				probs = append(probs, reservedAddress(domain, a.A.String()))
			}
		}
	}

	aaaaRRs, err := ctx.Lookup(domain, dns.TypeAAAA)
	if err != nil {
		probs = append(probs, dnsLookupFailed(domain, "AAAA", err))
	} else {
		for _, rr := range aaaaRRs {
			aaaa, ok := rr.(*dns.AAAA)
			if !ok {
				continue
			}
			recordCount++
			if isAddressReserved(aaaa.AAAA) {
				probs = append(probs, reservedAddress(domain, aaaa.AAAA.String()))
			}
		}
	}

	if recordCount == 0 {
		probs = append(probs, noRecords(domain, fmt.Sprintf("A: %v, AAAA: %v", aRRs, aaaaRRs)))
	}

	return probs, nil
}
