package letsdebug

import (
	"net"
	"strings"

	"fmt"

	"net/http"

	"time"

	"github.com/miekg/dns"
	"github.com/weppos/publicsuffix-go/net/publicsuffix"
	psl "github.com/weppos/publicsuffix-go/publicsuffix"
)

// validDomainChecker ensures that the FQDN is well-formed and is part of a public suffix.
type validDomainChecker struct{}

func (c validDomainChecker) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	var probs []Problem

	if strings.HasPrefix(domain, "*.") {
		domain = domain[2:]
	}

	for _, ch := range []byte(domain) {
		if (('a' <= ch && ch <= 'z') ||
			('A' <= ch && ch <= 'A') ||
			('0' <= ch && ch <= '9') ||
			ch == '.' || ch == '-') == false {
			probs = append(probs, invalidDomain(domain, fmt.Sprintf("Invalid character present: %c", ch)))
			return probs, nil
		}
	}

	if len(domain) > 230 {
		probs = append(probs, invalidDomain(domain, "Domain too long"))
		return probs, nil
	}

	if ip := net.ParseIP(domain); ip != nil {
		probs = append(probs, invalidDomain(domain, "Domain is an IP address"))
		return probs, nil
	}

	rule := psl.DefaultList.Find(domain, &psl.FindOptions{IgnorePrivate: true, DefaultRule: nil})
	if rule == nil {
		probs = append(probs, invalidDomain(domain, "Domain doesn't end in a public TLD"))
		return probs, nil
	}

	if rule.Decompose(domain)[1] == "" {
		probs = append(probs, invalidDomain(domain, "Domain is a TLD"))
		return probs, nil
	}

	return probs, nil
}

// caaChecker ensures that any caa record on the domain, or up the domain tree, allow issuance for letsencrypt.org
type caaChecker struct{}

func (c caaChecker) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	var probs []Problem

	wildcard := false
	if strings.HasPrefix(domain, "*.") {
		wildcard = true
		domain = domain[2:]
	}

	rrs, err := ctx.Lookup(domain, dns.TypeCAA)
	if err != nil {
		probs = append(probs, dnsLookupFailed(domain, "CAA", err))
		return probs, nil
	}

	// check any found caa records
	if len(rrs) > 0 {
		var issue []*dns.CAA
		var issuewild []*dns.CAA
		var criticalUnknown []*dns.CAA

		for _, rr := range rrs {
			caaRr, ok := rr.(*dns.CAA)
			if !ok {
				continue
			}

			switch caaRr.Tag {
			case "issue":
				issue = append(issue, caaRr)
			case "issuewild":
				issuewild = append(issuewild, caaRr)
			case "iodef":
				// TODO: should this print a notice that lets encrypt doesn't support iodef atm?
				// https://github.com/letsencrypt/boulder/issues/2580
			default:
				if caaRr.Flag == 1 {
					criticalUnknown = append(criticalUnknown, caaRr)
				}
			}
		}

		if len(criticalUnknown) > 0 {
			probs = append(probs, caaCriticalUnknown(domain, wildcard, criticalUnknown))
			return probs, nil
		}

		if len(issue) == 0 && !wildcard {
			return probs, nil
		}

		records := issue
		if wildcard && len(issuewild) > 0 {
			records = issuewild
		}

		for _, r := range records {
			if extractIssuerDomain(r.Value) == "letsencrypt.org" {
				return probs, nil
			}
		}

		probs = append(probs, caaIssuanceNotAllowed(domain, wildcard, records))
		return probs, nil
	}

	// recurse up to the public suffix domain until a caa record is found
	// a.b.c.com -> b.c.com -> c.com until
	if ps, _ := publicsuffix.PublicSuffix(domain); domain != ps && ps != "" {
		splitDomain := strings.SplitN(domain, ".", 2)

		parentProbs, err := c.Check(ctx, splitDomain[1], method)
		if err != nil {
			return nil, fmt.Errorf("error checking caa record on domain: %s, %v", splitDomain[1], err)
		}

		probs = append(probs, parentProbs...)
	}

	return probs, nil
}

func extractIssuerDomain(value string) string {
	// record can be:
	// issuedomain.tld; someparams
	return strings.Trim(strings.SplitN(value, ";", 2)[0], " \t")
}

func collateRecords(records []*dns.CAA) string {
	var s []string
	for _, r := range records {
		s = append(s, r.String())
	}
	return strings.Join(s, "\n")
}

func caaCriticalUnknown(domain string, wildcard bool, records []*dns.CAA) Problem {
	return Problem{
		Name: "CaaCriticalUnknown",
		Explanation: fmt.Sprintf(`CAA record(s) exist on %s (wildcard=%t) that are marked as critical but are unknown to Let's Encrypt. `+
			`These record(s) as shown in the detail must be removed, or marked as non-critical, before a certificate can be issued by the Let's Encrypt CA.`, domain, wildcard),
		Detail:   collateRecords(records),
		Severity: SeverityFatal,
	}
}

func caaIssuanceNotAllowed(domain string, wildcard bool, records []*dns.CAA) Problem {
	return Problem{
		Name: "CaaIssuanceNotAllowed",
		Explanation: fmt.Sprintf(`No CAA record on %s (wildcard=%t) contains the issuance domain "letsencrypt.org". `+
			`You must either add an additional record to include "letsencrypt.org" or remove every existing CAA record. `+
			`A list of the CAA records are provided in the details.`, domain, wildcard),
		Detail:   collateRecords(records),
		Severity: SeverityFatal,
	}
}

func invalidDomain(domain, reason string) Problem {
	return Problem{
		Name:        "InvalidDomain",
		Explanation: fmt.Sprintf(`"%s" is not a valid domain name that Let's Encrypt would be able to issue a certificate for.`, domain),
		Detail:      reason,
		Severity:    SeverityFatal,
	}
}

// cloudflareChecker determines if the domain is using cloudflare, and whether a certificate has been provisioned by cloudflare yet.
type cloudflareChecker struct{}

func (c cloudflareChecker) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	var probs []Problem

	cl := http.Client{
		Timeout: httpTimeout * time.Second,
	}
	resp, err := cl.Get("https://" + domain)
	if err == nil { // no tls error, cert must be issued
		// check if it's cloudflare
		if hasCloudflareHeader(resp.Header) {
			probs = append(probs, cloudflareCDN(domain))
		}

		return probs, nil
	}

	// disable redirects
	cl.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// attempt to connect over http with redirects disabled to check cloudflare header
	resp, err = cl.Get("http://" + domain)
	if err != nil {
		return probs, nil
	}

	if hasCloudflareHeader(resp.Header) {
		probs = append(probs, cloudflareCDN(domain))
		probs = append(probs, cloudflareSslNotProvisioned(domain))
	}

	return probs, nil
}

func hasCloudflareHeader(h http.Header) bool {
	return strings.Contains(strings.ToLower(h.Get("server")), "cloudflare")
}

func cloudflareCDN(domain string) Problem {
	return Problem{
		Name: "CloudflareCDN",
		Explanation: fmt.Sprintf(`The domain %s is being served through Cloudflare CDN. Any Let's Encrypt certificate installed on the `+
			`origin server will only encrypt traffic between the server and Cloudflare. It is strongly recommended that the SSL option 'Full SSL (strict)' `+
			`be enabled.`, domain),
		Detail:   "https://support.cloudflare.com/hc/en-us/articles/200170416-What-do-the-SSL-options-mean-",
		Severity: SeverityWarning,
	}
}

func cloudflareSslNotProvisioned(domain string) Problem {
	return Problem{
		Name:        "CloudflareSSLNotProvisioned",
		Explanation: fmt.Sprintf(`The domain %s is being served through Cloudflare CDN and a certificate has not yet been provisioned yet by Cloudflare.`, domain),
		Detail:      "https://support.cloudflare.com/hc/en-us/articles/203045244-How-long-does-it-take-for-Cloudflare-s-SSL-to-activate-",
		Severity:    SeverityWarning,
	}
}
