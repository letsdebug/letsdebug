package letsdebug

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
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
		Explanation: fmt.Sprintf(`An error occured while attempting to lookup the TXT record on _acme-challenge.%s . `+
			`Any resolver errors that the Let's Encrypt CA encounters on this record will cause certificate issuance to fail.`, domain),
		Detail:   err.Error(),
		Severity: SeverityFatal,
	}
}
