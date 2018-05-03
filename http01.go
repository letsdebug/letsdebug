package letsdebug

import (
	"fmt"
	"net"
	"strings"
	"sync"

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
	var aRRs, aaaaRRs []dns.RR
	var aErr, aaaaErr error

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		aaaaRRs, aaaaErr = ctx.Lookup(domain, dns.TypeAAAA)
	}()

	go func() {
		defer wg.Done()
		aRRs, aErr = ctx.Lookup(domain, dns.TypeA)
	}()

	wg.Wait()

	if aErr != nil {
		probs = append(probs, dnsLookupFailed(domain, "A", aErr))
	}
	if aaaaErr != nil {
		probs = append(probs, dnsLookupFailed(domain, "AAAA", aaaaErr))
	}

	for _, rr := range aRRs {
		if aRR, ok := rr.(*dns.A); ok && isAddressReserved(aRR.A) {
			probs = append(probs, reservedAddress(domain, aRR.A.String()))
		}
	}
	for _, rr := range aaaaRRs {
		if aaaaRR, ok := rr.(*dns.AAAA); ok && isAddressReserved(aaaaRR.AAAA) {
			probs = append(probs, reservedAddress(domain, aaaaRR.AAAA.String()))
		}
	}

	var sb []string
	for _, rr := range append(aRRs, aaaaRRs...) {
		sb = append(sb, rr.String())
	}

	if len(sb) > 0 {
		probs = append(probs, debugProblem("HTTPRecords", "A and AAAA records found for this domain", strings.Join(sb, "\n")))
	}

	if len(sb) == 0 {
		probs = append(probs, noRecords(domain, "No A or AAAA records found."))
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
		return probs, nil
	}

	// Track one response from IPv4 and one response from IPv6
	// in order to check whether they might be pointing to different servers
	var v4Res httpCheckResult
	var v6Res httpCheckResult

	var debug []string

	for _, ip := range ips {
		res, prob := checkHTTP(ctx, domain, ip)
		if !prob.IsZero() {
			probs = append(probs, prob)
		}
		if v4Res.IsZero() && ip.To4() != nil {
			v4Res = res
		} else if v6Res.IsZero() {
			v6Res = res
		}
		debug = append(debug, fmt.Sprintf("Request to: %s/%s, Result: %s, Issue: %s",
			domain, ip.String(), res.String(), prob.Name))
	}

	if (!v4Res.IsZero() && !v6Res.IsZero()) && (v4Res.StatusCode != v6Res.StatusCode || v4Res.ServerHeader != v6Res.ServerHeader) {
		probs = append(probs, v4v6Discrepancy(domain, v4Res, v6Res))
	}

	probs = append(probs, debugProblem("HTTPCheck", "Requests made to the domain", strings.Join(debug, "\n")))

	return probs, nil
}

func noRecords(name, rrSummary string) Problem {
	return Problem{
		Name: "NoRecords",
		Explanation: fmt.Sprintf(`No valid A or AAAA records could be ultimately resolved for %s. `+
			`This means that Let's Encrypt would not be able to to connect to your domain to perform HTTP validation, since `+
			`it would not know where to connect to.`, name),
		Detail:   rrSummary,
		Severity: SeverityFatal,
	}
}

func reservedAddress(name, address string) Problem {
	return Problem{
		Name: "ReservedAddress",
		Explanation: fmt.Sprintf(`A private, inaccessible, IANA/IETF-reserved IP address was found for %s. Let's Encrypt will always fail HTTP validation `+
			`for any domain that is pointing to an address that is not routable on the internet. You should either remove this address `+
			`and replace it with a public one or use the DNS validation method instead.`, name),
		Detail:   address,
		Severity: SeverityFatal,
	}
}

func v4v6Discrepancy(domain string, v4Result, v6Result httpCheckResult) Problem {
	return Problem{
		Name: "IPv4IPv6Discrepancy",
		Explanation: fmt.Sprintf(`%s has both AAAA (IPv6) and A (IPv4) records. While they both appear to be accessible on the network, `+
			`we have detected that they produce differing results when sent an ACME HTTP validation request. This may indicate that `+
			`the IPv4 and IPv6 addresses may unintentionally point to different servers, which would cause validation to fail.`,
			domain),
		Detail:   fmt.Sprintf("%s vs %s", v4Result.String(), v6Result.String()),
		Severity: SeverityWarning,
	}
}
