package letsdebug

import (
	"fmt"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/weppos/publicsuffix-go/publicsuffix"
)

// wildcardDns01OnlyChecker ensures that a wildcard domain is only validated via dns-01.
type wildcardDns01OnlyChecker struct{}

func (c wildcardDns01OnlyChecker) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	if !strings.HasPrefix(domain, "*.") {
		return nil, errNotApplicable
	}

	if method == DNS01 {
		return nil, errNotApplicable
	}

	return []Problem{wildcardHttp01(domain, method)}, nil
}

func wildcardHttp01(domain string, method ValidationMethod) Problem {
	return Problem{
		Name:        "MethodNotSuitable",
		Explanation: fmt.Sprintf("A wildcard domain like %s can only be issued using a dns-01 validation method.", domain),
		Detail:      fmt.Sprintf("Invalid method: %s", method),
		Severity:    SeverityFatal,
	}
}

// txtRecordChecker ensures there is no resolution errors with the _acme-challenge txt record
type txtRecordChecker struct{}

func (c txtRecordChecker) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	if method != DNS01 {
		return nil, errNotApplicable
	}

	if strings.HasPrefix(domain, "*.") {
		domain = domain[2:]
	}

	if _, err := ctx.Lookup("_acme-challenge."+domain, dns.TypeTXT); err != nil {
		// report this problem as a fatal problem as that is the purpose of this checker
		return []Problem{txtRecordError(domain, err)}, nil
	}

	return nil, nil
}

func txtRecordError(domain string, err error) Problem {
	return Problem{
		Name: "TXTRecordError",
		Explanation: fmt.Sprintf(`An error occurred while attempting to lookup the TXT record on _acme-challenge.%s . `+
			`Any resolver errors that the Let's Encrypt CA encounters on this record will cause certificate issuance to fail.`, domain),
		Detail:   err.Error(),
		Severity: SeverityFatal,
	}
}

// txtDoubledLabelChecker ensures that a record for _acme-challenge.example.org.example.org
// wasn't accidentally created
type txtDoubledLabelChecker struct{}

func (c txtDoubledLabelChecker) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	if method != DNS01 {
		return nil, errNotApplicable
	}

	registeredDomain, _ := publicsuffix.Domain(domain)

	variants := []string{
		fmt.Sprintf("_acme-challenge.%s.%s", domain, domain),           // _acme-challenge.www.example.org.www.example.org
		fmt.Sprintf("_acme-challenge.%s.%s", domain, registeredDomain), // _acme-challenge.www.example.org.example.org
	}

	var found []string
	var foundMu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(2)

	for _, variant := range variants {
		go func(q string) {
			defer wg.Done()
			rrs, _ := ctx.Lookup(q, dns.TypeTXT) // Don't worry if the lookup failed
			foundMu.Lock()
			defer foundMu.Unlock()
			for _, rr := range rrs {
				txt, ok := rr.(*dns.TXT)
				if !ok {
					continue
				}
				if len(txt.Txt) > 0 {
					found = append(found, q)
				}
			}
		}(variant)
	}

	wg.Wait()

	if len(found) > 0 {
		return []Problem{Problem{
			Name: "TXTDoubleLabel",
			Explanation: "Some DNS records were found that indicate TXT records having been incorrectly manually entered into " +
				`DNS editor interfaces. The correct way to enter these records is to either remove the domain from the label (so ` +
				`"_acme-challenge.example.org" is entered just as "_acme-challenge.www") or include a period (.) at the ` +
				`end of the label (so "_acme-challenge.example.org.").`,
			Detail:   fmt.Sprintf("The following probably-erroneous TXT records were found:\n%s", strings.Join(found, "\n")),
			Severity: SeverityWarning,
		}}, nil
	}

	return nil, nil
}
