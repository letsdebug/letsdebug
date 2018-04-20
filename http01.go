package letsdebug

import (
	"fmt"
	"net"

	"github.com/miekg/dns"
)

// aaaaInaccessibilityChecker checks whether a domain is advertising AAAA records
// that are not accessible over HTTP/port 80.
type aaaaInaccessibilityChecker struct {
}

func aaaaNotWorking(domain, ipv6Address string, err error) Problem {
	return Problem{
		Name: "AAAANotWorking",
		Explanation: fmt.Sprintf(`%s has an AAAA (IPv6) record (%s) but it is not responding to HTTP requests over port 80. `+
			`This is a problem because Let's Encrypt will prefer to use AAAA records, if present, and will not fall back to IPv4 records. `+
			`You should either repair the domain's IPv6 connectivity, or remove its AAAA record.`,
			domain, ipv6Address),
		Detail:   err.Error(),
		Priority: PriorityError,
	}
}

func (c aaaaInaccessibilityChecker) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	if method != HTTP01 {
		return nil, errNotApplicable
	}

	var probs []Problem

	rrs, err := ctx.Lookup(domain, dns.TypeAAAA)
	if err != nil {
		probs = append(probs, dnsLookupFailed(domain, "AAAA", err))
		return probs, nil
	}

	var ips []net.IP

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

func noRecords(name, rrSummary string) Problem {
	return Problem{
		Name: "NoRecords",
		Explanation: fmt.Sprintf(`No valid A or AAAA records could be ultimately resolved for %s (including indirection via CNAME). `+
			`This means that Let's Encrypt would not be able to to connect to your domain to perform HTTP validation, since `+
			`it would not know where to connect to.`, name),
		Detail:   rrSummary,
		Priority: PriorityError,
	}
}

func reservedAddress(name, address string) Problem {
	return Problem{
		Name: "ReservedAddress",
		Explanation: fmt.Sprintf(`An IANA/IETF-reserved address was found for %s. Let's Encrypt will always fail HTTP validation `+
			`for any domain that is pointing to an address that is not routable on the internet. You should either remove this address `+
			`or use the DNS validation method instead.`, name),
		Detail:   address,
		Priority: PriorityError,
	}
}

func (c reservedAddressChecker) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	if method != HTTP01 {
		return nil, errNotApplicable
	}

	var probs []Problem
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
