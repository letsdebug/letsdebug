package letsdebug

import (
	"fmt"
	"strings"
)

// wildcardDns01OnlyChecker ensures that a wildcard domain is only validated via dns-01.
type wildcardDns01OnlyChecker struct{}

func (c wildcardDns01OnlyChecker) PreFlight(ctx *scanContext, domain string, method ValidationMethod) error {
	if !strings.HasPrefix(domain, "*.") || method == DNS01 {
		return errNotApplicable
	}

	return nil
}

func (c wildcardDns01OnlyChecker) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	return []Problem{wildcardHttp01(domain, method)}, nil
}

func wildcardHttp01(domain string, method ValidationMethod) Problem {
	return Problem{
		Name:        "WildcardOverDNS01Only",
		Explanation: fmt.Sprintf("A wildcard domain like %s can only be issued using a dns-01 validation method.", domain),
		Detail:      fmt.Sprintf("Invalid method: %s", method),
		Severity:    SeverityFatal,
	}
}
