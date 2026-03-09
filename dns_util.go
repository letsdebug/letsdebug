package letsdebug

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var (
	reservedNets []*net.IPNet
	cfClient     *dns.Client
)

func lookup(name string, rrType uint16) ([]dns.RR, error) {
	result, err := lookupRaw(name, rrType)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	return result.RRs, nil
}

func lookupRaw(name string, rrType uint16) (*LookupResult, error) {
	res, err := GetResolver().Lookup(name, rrType, 60*time.Second)
	if err != nil {
		return nil, err
	}

	// If the resolver reports DNSSEC Bogus, try to fetch additional EDE text from Cloudflare.
	if res != nil && res.Bogus {
		err := fmt.Errorf("DNS response for %s had fatal DNSSEC issues: %v", name, res.WhyBogus)
		if edeText, _ := lookupCloudflareEDE(name, rrType); edeText != "" {
			err = fmt.Errorf("%s. Additionally, Cloudflare's 1.1.1.1 resolver reported: %s", err.Error(), edeText)
		}
		return res, err
	}

	// Map NXDOMAIN-like state for callers that expect NxDomain information.
	if res != nil && (res.Rcode == dns.RcodeServerFailure || res.Rcode == dns.RcodeRefused) {
		return res, fmt.Errorf("DNS response for %s/%s did not have an acceptable response code: %s", name, dns.TypeToString[rrType], dns.RcodeToString[res.Rcode])
	}

	return res, nil
}

func lookupCloudflareEDE(name string, rrType uint16) (string, error) {
	q := &dns.Msg{}
	q.SetQuestion(name+".", rrType)
	q.SetEdns0(4096, true)
	q.RecursionDesired = true

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	r, _, err := cfClient.ExchangeContext(ctx, q, "1.1.1.1:53")
	if err != nil {
		return "", err
	}

	var ede *dns.EDNS0_EDE
	opt := r.IsEdns0()
	if opt == nil {
		return "", nil
	}
	for _, opt := range opt.Option {
		if asEDE, ok := opt.(*dns.EDNS0_EDE); ok {
			ede = asEDE
			break
		}
	}
	if ede == nil {
		return "", nil
	}

	if ede.ExtraText != "" {
		return ede.ExtraText, nil
	}

	return "", nil
}

func normalizeFqdn(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, ".")
	return strings.ToLower(name)
}

func isAddressReserved(ip net.IP) bool {
	for _, reserved := range reservedNets {
		if reserved.Contains(ip) {
			return true
		}
	}
	return false
}

func init() {
	reservedNets = []*net.IPNet{}
	reservedCIDRs := []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10",
		"127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
		"192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"255.255.255.255/32", "::/128", "::1/128", /*"::ffff:0:0/96",*/
		"64:ff9b::/96", "100::/64", "2001::/32", "2001:10::/28",
		"2001:20::/28", "2001:db8::/32", "2002::/16", "fc00::/7",
		"fe80::/10", "ff00::/8",
	}
	for _, cidr := range reservedCIDRs {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		reservedNets = append(reservedNets, n)
	}
	cfClient = &dns.Client{}
}
