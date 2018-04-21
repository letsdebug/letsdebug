package letsdebug

import (
	"fmt"
	"net"

	"github.com/miekg/dns"
)

// dnsAChecker checks if there are any issues in Unbound looking up the A and
// AAAA records for a domain (such as DNSSEC issues or dead nameservers)
type dnsAChecker struct{}

func (c dnsAChecker) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	if method != HTTP01 {
		return nil, errNotApplicable
	}

	var probs []Problem

	_, err := ctx.Lookup(domain, dns.TypeAAAA)
	if err != nil {
		probs = append(probs, dnsLookupFailed(domain, "AAAA", err))
	}

	_, err = ctx.Lookup(domain, dns.TypeA)
	if err != nil {
		probs = append(probs, dnsLookupFailed(domain, "A", err))
	}

	return probs, nil
}

// httpAccessibilityChecker checks whether an HTTP ACME validation request
// would lead to any issues such as:
// - Bad redireects
// - IPs not listening on port 80
type httpAccessibilityChecker struct{}

func (c httpAccessibilityChecker) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	if method != HTTP01 {
		return nil, errNotApplicable
	}

	var probs []Problem

	var ips []net.IP

	rrs, _ := ctx.Lookup(domain, dns.TypeAAAA)
	for _, rr := range rrs {
		aaaa, ok := rr.(*dns.AAAA)
		if !ok {
			continue
		}
		ips = append(ips, aaaa.AAAA)
	}
	rrs, _ = ctx.Lookup(domain, dns.TypeA)
	for _, rr := range rrs {
		a, ok := rr.(*dns.A)
		if !ok {
			continue
		}
		ips = append(ips, a.A)
	}

	if len(ips) == 0 {
		probs = append(probs, noRecords(domain, "No A or AAAA records found."))
	}

	for _, ip := range ips {
		if isAddressReserved(ip) {
			probs = append(probs, reservedAddress(domain, ip.String()))
			continue
		}
		if prob := checkHTTP(domain, ip); !prob.IsZero() {
			probs = append(probs, prob)
		}
	}

	return probs, nil
}

func noRecords(name, rrSummary string) Problem {
	return Problem{
		Name: "NoRecords",
		Explanation: fmt.Sprintf(`No valid A or AAAA records could be ultimately resolved for %s (including indirection via CNAME). `+
			`This means that Let's Encrypt would not be able to to connect to your domain to perform HTTP validation, since `+
			`it would not know where to connect to.`, name),
		Detail:   rrSummary,
		Severity: SeverityError,
	}
}

func reservedAddress(name, address string) Problem {
	return Problem{
		Name: "ReservedAddress",
		Explanation: fmt.Sprintf(`An IANA/IETF-reserved address was found for %s. Let's Encrypt will always fail HTTP validation `+
			`for any domain that is pointing to an address that is not routable on the internet. You should either remove this address `+
			`or use the DNS validation method instead.`, name),
		Detail:   address,
		Severity: SeverityError,
	}
}
