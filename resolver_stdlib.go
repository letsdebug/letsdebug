//go:build !linux

package letsdebug

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// StdlibResolver uses the standard network stack (via a dns.Client against
// system-configured nameservers) to perform queries. It intentionally does
// not perform DNSSEC validation; Bogus will always be false.
type StdlibResolver struct {
	client  *dns.Client
	servers []string
}

func defaultResolver() Resolver {
	return &StdlibResolver{}
}

func (s *StdlibResolver) ensureClient() {
	if s.client == nil {
		s.client = &dns.Client{}
		// Try to load system resolvers from /etc/resolv.conf. If that fails,
		// fall back to Google's public resolver.
		if cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil && len(cfg.Servers) > 0 {
			for _, srv := range cfg.Servers {
				s.servers = append(s.servers, net.JoinHostPort(srv, cfg.Port))
			}
		} else {
			s.servers = []string{"8.8.8.8:53"}
		}
	}
}

func (s *StdlibResolver) Lookup(name string, rrType uint16, timeout time.Duration) (*LookupResult, error) {
	s.ensureClient()
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), rrType)
	q.RecursionDesired = true
	q.SetEdns0(4096, true)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var lastErr error
	for _, srv := range s.servers {
		resp, _, err := s.client.ExchangeContext(ctx, q, srv)
		if err != nil {
			lastErr = err
			continue
		}
		// Build LookupResult
		out := &LookupResult{
			RRs:      resp.Answer,
			Rcode:    resp.Rcode,
			Bogus:    false,
			WhyBogus: "",
			NxDomain: resp.Rcode == dns.RcodeNameError,
		}
		return out, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no DNS servers configured to perform lookup")
}
