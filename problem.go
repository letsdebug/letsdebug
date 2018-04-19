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
