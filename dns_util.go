package letsdebug

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
	"github.com/miekg/unbound"
)

var (
	reservedNets []*net.IPNet
)

func lookup(name string, rrType uint16) ([]dns.RR, error) {
	ub := unbound.New()
	defer ub.Destroy()

	if err := setUnboundConfig(ub); err != nil {
		return nil, fmt.Errorf("Failed to configure Unbound resolver: %v", err)
	}

	result, err := ub.Resolve(name, rrType, dns.ClassINET)
	if err != nil {
		return nil, err
	}

	if result.Bogus {
		return nil, fmt.Errorf("Response for %s was bogus: %v", name, result.WhyBogus)
	}

	return result.Rr, nil
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
}

func setUnboundConfig(ub *unbound.Unbound) error {
	// options need the : in the option key according to docs
	opts := []struct {
		Opt string
		Val string
	}{
		{"verbosity:", "0"},
		{"num-threads:", "1"},
		{"so-reuseport:", "yes"},
		{"use-syslog:", "no"},
		{"do-ip4:", "yes"},
		{"do-ip6:", "yes"},
		{"do-udp:", "yes"},
		{"do-tcp:", "yes"},
		{"tcp-upstream:", "no"},
		{"harden-glue:", "yes"},
		{"harden-dnssec-stripped:", "yes"},
		{"use-caps-for-id:", "yes"},
		{"cache-min-ttl:", "0"},
		{"cache-max-ttl:", "0"},
		{"cache-max-negative-ttl:", "0"},
		{"neg-cache-size:", "0"},
		{"prefetch:", "no"},
		{"unwanted-reply-threshold:", "10000"},
		{"do-not-query-localhost:", "yes"},
		{"val-clean-additional:", "yes"},
		{"harden-algo-downgrade:", "yes"},
	}

	for _, opt := range opts {
		// no matter what, error always returns "syntax error" even when the option is successfully set
		// eg try changing verbosity to 5 and watch stderr output
		ub.SetOption(opt.Opt, opt.Val)
	}

	return ub.AddTa(`. 111013 IN DNSKEY 257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjF FVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoX bfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaD X6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpz W5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relS Qageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulq QxA+Uk1ihz0=
. 111013 IN DNSKEY 256 3 8 AwEAAdU4aKlDgEpXWWpH5aXHJZI1Vm9Cm42mGAsqkz3akFctS6zsZHC3 pNNMug99fKa7OW+tRHIwZEc//mX8Jt6bcw5bPgRHG6u2eT8vUpbXDPVs 1ICGR6FhlwFWEOyxbIIiDfd7Eq6eALk5RNcauyE+/ZP+VdrhWZDeEWZR rPBLjByBWTHl+v/f+xvTJ3Stcq2tEqnzS2CCOr6RTJepprYhu+5Yl6aR ZmEVBK27WCW1Zrk1LekJvJXfcyKSKk19C5M5JWX58px6nB1IS0pMs6aC IK2yaQQVNUEg9XyQzBSv/rMxVNNy3VAqOjvh+OASpLMm4GECbSSe8jtj wG0I78sfMZc=
. 111013 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3 +/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kv ArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF 0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+e oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfd RUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwN R1AkUTV74bU=`)
}
