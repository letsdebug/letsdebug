package letsdebug

import (
	"fmt"
)

// Problem represents an issue found by one of the checkers in this package.
// Explanation is a human-readable explanation of the issue.
// Detail is usually the underlying machine error.
type Problem struct {
	Name        string
	Explanation string
	Detail      string
}

func (p Problem) String() string {
	return fmt.Sprintf("[%s] %s: %s", p.Name, p.Explanation, p.Detail)
}

func internalProblem(message string) Problem {
	return Problem{
		Name:        "InternalProblem",
		Explanation: fmt.Sprintf("An internal error occured while checking the domain"),
		Detail:      message,
	}
}

func aaaaNotWorking(domain, ipv6Address string, err error) Problem {
	return Problem{
		Name: "AAAANotWorking",
		Explanation: fmt.Sprintf(`%s has an AAAA (IPv6) record (%s) but it is not responding to HTTP requests over port 80. `+
			`This is a problem because Let's Encrypt will prefer to use AAAA records, if present, and will not fall back to IPv4 records. `+
			`You should either repair the domain's IPv6 connectivity, or remove its AAAA record.`,
			domain, ipv6Address),
		Detail: err.Error(),
	}
}

func dnsLookupFailed(name, rrType string, err error) Problem {
	return Problem{
		Name:        "DNSLookupFailed",
		Explanation: fmt.Sprintf(`A fatal issue occured during the DNS lookup process for %s/%s.`, name, rrType),
		Detail:      err.Error(),
	}
}

func noRecords(name, rrSummary string) Problem {
	return Problem{
		Name: "NoRecords",
		Explanation: fmt.Sprintf(`No valid A or AAAA records could be ultimately resolved for %s (including indirection via CNAME). `+
			`This means that Let's Encrypt would not be able to to connect to your domain to perform HTTP validation, since `+
			`it would not know where to connect to.`, name),
		Detail: rrSummary,
	}
}

func reservedAddress(name, address string) Problem {
	return Problem{
		Name: "ReservedAddress",
		Explanation: fmt.Sprintf(`An IANA/IETF-reserved address was found for %s. Let's Encrypt will always fail HTTP validation `+
			`for any domain that is pointing to an address that is not routable on the internet. You should either remove this address `+
			`or use the DNS validation method instead.`, name),
		Detail: address,
	}
}
