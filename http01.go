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

	// Track one response from IPv4 and one response from IPv6
	// in order to check whether they might be pointing to different servers
	var v4Res httpCheckResult
	var v6Res httpCheckResult

	for _, ip := range ips {
		if isAddressReserved(ip) {
			probs = append(probs, reservedAddress(domain, ip.String()))
			continue
		}
		res, prob := checkHTTP(domain, ip)
		if !prob.IsZero() {
			probs = append(probs, prob)
		}
		if v4Res.IsZero() && ip.To4() != nil {
			v4Res = res
		} else if v6Res.IsZero() {
			v6Res = res
		}
	}

	if (!v6Res.IsZero() && !v6Res.IsZero()) && (v4Res.StatusCode != v6Res.StatusCode || v4Res.ServerHeader != v6Res.ServerHeader) {
		probs = append(probs, v4v6Discrepancy(domain, v4Res, v6Res))
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

func v4v6Discrepancy(domain string, v4Result, v6Result httpCheckResult) Problem {
	return Problem{
		Name: "IPv6Ipv6Discrepancy",
		Explanation: fmt.Sprintf(`%s has both AAAA (IPv6) and A (IPv4) records. While they both appear to be accessible on the network, `+
			`we have detected that they produce differing results when sent an ACME HTTP validation request. This may indicate that `+
			`the IPv4 and IPv6 addresses may unintentionally point to different servers, which would cause validation to fail.`,
			domain),
		Detail:   fmt.Sprintf("%s vs %s", v4Result.String(), v6Result.String()),
		Severity: SeverityWarning,
	}
}
