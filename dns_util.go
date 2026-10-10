package letsdebug

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/miekg/unbound"
	"golang.org/x/net/context"
)

var (
	reservedNets []*net.IPNet
	cfClient     *dns.Client
	_ub          *unbound.Unbound
	once         sync.Once
)

func getUnbound() *unbound.Unbound {
	once.Do(func() {
		_ub = unbound.New()

		if err := setUnboundConfig(_ub); err != nil {
			log.Fatalf("failed to configure Unbound resolver: %v", err)
		}
	})
	return _ub
}

func lookup(name string, rrType uint16) ([]dns.RR, error) {
	result, err := lookupRaw(name, rrType)
	if err != nil {
		return nil, err
	}

	return result.Rr, nil
}

func lookupRaw(name string, rrType uint16) (*unbound.Result, error) {

	result, err := lookupWithTimeout(name, rrType, 60*time.Second)
	if err != nil {
		return nil, err
	}

	if result.Bogus {
		err = fmt.Errorf("DNS response for %s had fatal DNSSEC issues: %v", name, result.WhyBogus)
		if edeText, _ := lookupCloudflareEDE(name, rrType); edeText != "" {
			err = fmt.Errorf(
				"%s. Additionally, Cloudflare's 1.1.1.1 resolver reported: %s",
				err.Error(), edeText)
		}
		return result, err
	}

	if result.Rcode == dns.RcodeServerFailure || result.Rcode == dns.RcodeRefused {
		fmt.Printf("unbound servfail/refused result: %+v\n", result)
		return result, fmt.Errorf("DNS response for %s/%s did not have an acceptable response code: %s",
			name, dns.TypeToString[rrType], dns.RcodeToString[result.Rcode])
	}

	return result, nil
}

func lookupWithTimeout(name string, rrType uint16, timeout time.Duration) (*unbound.Result, error) {
	type unboundWrapper struct {
		result *unbound.Result
		err    error
	}

	ub := getUnbound()
	resultChan := make(chan unboundWrapper, 1)

	go func() {
		result, err := ub.Resolve(name, rrType, dns.ClassINET)
		resultChan <- unboundWrapper{result, err}
	}()

	select {
	case res := <-resultChan:
		return res.result, res.err
	case <-time.After(timeout):
		return nil, fmt.Errorf("DNS response for %s/%s could not be resolved within the timeout. This may indicate slow or unresponsive nameservers", name, dns.TypeToString[rrType])
	}
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

func setUnboundConfig(ub *unbound.Unbound) error {
	// options need the : in the option key according to docs
	opts := []struct {
		Opt string
		Val string
	}{
		{"verbosity:", "1"},
		{"log-servfail:", "yes"},
		{"use-syslog:", "no"},
		{"do-ip4:", "yes"},
		{"do-ip6:", "yes"},
		{"do-udp:", "yes"},
		{"do-tcp:", "yes"},
		{"tcp-upstream:", "no"},
		{"harden-glue:", "yes"},
		{"harden-dnssec-stripped:", "yes"},
		{"cache-min-ttl:", "0"},
		{"cache-max-ttl:", "60"},
		{"cache-max-negative-ttl:", "0"},
		{"neg-cache-size:", "0"},
		{"prefetch:", "no"},
		{"unwanted-reply-threshold:", "10000"},
		{"do-not-query-localhost:", "yes"},
		{"val-clean-additional:", "yes"},
		{"harden-algo-downgrade:", "yes"},
		{"edns-buffer-size:", "1232"},
		{"val-sig-skew-min:", "0"},
		{"val-sig-skew-max:", "0"},
		{"so-reuseport:", "yes"},
		{"qname-minimisation:", "no"},
		{"qname-minimisation-strict:", "no"},
	}

	for _, opt := range opts {
		// Can't ignore these because we cant silently have policies being ignored
		if err := ub.SetOption(opt.Opt, opt.Val); err != nil {
			return fmt.Errorf("failed to configure unbound with option %s %v", opt.Opt, err)
		}
	}

	// use-caps-for-id was bugged (no colon) < 1.7.1, try both ways in order to be compatible
	// https://www.nlnetlabs.nl/bugs-script/show_bug.cgi?id=4092
	if err := ub.SetOption("use-caps-for-id:", "yes"); err != nil {
		if err = ub.SetOption("use-caps-for-id", "yes"); err != nil {
			return fmt.Errorf("failed to configure unbound with use-caps-for-id: %v", err)
		}
	}

	// Root zone trust anchors, from https://data.iana.org/root-anchors/root-anchors.xml
	// libunbound parses a single RR per AddTa call, so each anchor is added separately.
	rootAnchors := []string{
		// KSK-2017
		". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
		// KSK-2024
		". IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
	}
	for _, ta := range rootAnchors {
		if err := ub.AddTa(ta); err != nil {
			return fmt.Errorf("failed to add root trust anchor %q: %v", ta, err)
		}
	}

	return nil
}
