package letsdebug

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	httpTimeout = 10
)

func checkHTTP(domain string, address net.IP) Problem {
	dialer := net.Dialer{
		Timeout: httpTimeout * time.Second,
	}
	cl := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				_, port, _ := net.SplitHostPort(addr)
				if address.To4() == nil {
					return dialer.DialContext(ctx, "tcp", "["+address.String()+"]:"+port)
				}
				return dialer.DialContext(ctx, "tcp", address.String()+":"+port)
			},
		},
	}

	req, err := http.NewRequest("GET", "http://"+domain+"/.well-known/acme-challenge/letsdebug-test", nil)
	if err != nil {
		return internalProblem(fmt.Sprintf("Failed to construct validation request: %v", err), SeverityError)
	}

	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout*time.Second)
	defer cancel()

	req = req.WithContext(ctx)

	resp, err := cl.Do(req)
	if err != nil {
		return translateHTTPError(domain, address, err)
	}

	defer resp.Body.Close()

	return Problem{}
}

func translateHTTPError(domain string, address net.IP, e error) Problem {
	if strings.HasSuffix(e.Error(), "http: server gave HTTP response to HTTPS client") {
		return httpServerMisconfiguration(domain, "Web server is serving the wrong protocol on the wrong port: "+e.Error()+
			". This may be due to a previous HTTP redirect rather than a webserver misconfiguration.")
	}

	if address.To4() == nil {
		return aaaaNotWorking(domain, address.String(), e)
	} else {
		return aNotWorking(domain, address.String(), e)
	}
}

func httpServerMisconfiguration(domain, detail string) Problem {
	return Problem{
		Name:        "WebserverMisconfiguration",
		Explanation: fmt.Sprintf(`%s's webserver may be misconfigured.`, domain),
		Detail:      detail,
		Severity:    SeverityError,
	}
}

func aaaaNotWorking(domain, ipv6Address string, err error) Problem {
	return Problem{
		Name: "AAAANotWorking",
		Explanation: fmt.Sprintf(`%s has an AAAA (IPv6) record (%s) but a test ACME validation request over port 80 has revealed problems. `+
			`Let's Encrypt will prefer to use AAAA records, if present, and will not fall back to IPv4 records. `+
			`You should either ensure that validation requests succeed over IPv6, or remove its AAAA record.`,
			domain, ipv6Address),
		Detail:   err.Error(),
		Severity: SeverityError,
	}
}

func aNotWorking(domain, addr string, err error) Problem {
	return Problem{
		Name: "ANotWorking",
		Explanation: fmt.Sprintf(`%s has an A (IPv4) record (%s) but a test ACME validation request over port 80 has revealed problems.`,
			domain, addr),
		Detail:   err.Error(),
		Severity: SeverityError,
	}
}
