package letsdebug

import (
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

	result, err := ub.Resolve(name, rrType, dns.ClassINET)
	if err != nil {
		return nil, err
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
		"255.255.255.255/32", "::/128", "::1/128", "::ffff:0:0/96",
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
