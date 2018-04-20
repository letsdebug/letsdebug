package letsdebug

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/miekg/unbound"
)

var (
	reservedNets  []*net.IPNet
	writeUbConfig sync.Once
)

func lookup(name string, rrType uint16) ([]dns.RR, error) {
	ubConfigPath := filepath.Join(os.TempDir(), "letsdebug-unbound.conf")
	writeUbConfig.Do(func() {
		if err := ioutil.WriteFile(ubConfigPath, []byte(unboundConf), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write Unbound config to disk: %v\n", err)
		}
		if err := ioutil.WriteFile(filepath.Join(os.TempDir(), "letsdebug_unbound_root.key"), []byte(unboundRootKey), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write Unbound root key to disk: %v\n", err)
		}
	})

	ub := unbound.New()
	defer ub.Destroy()

	if err := ub.Config(ubConfigPath); err != nil {
		return nil, fmt.Errorf("Failed to configure Unbound resolver: %v", err)
	}

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

var unboundConf = `
server:
	verbosity: 0
	num-threads: 1
	so-reuseport: yes
	use-syslog: no
	do-ip4: yes
	do-ip6: yes
	do-udp: yes
	do-tcp: yes
	tcp-upstream: no
	harden-glue: yes
	harden-dnssec-stripped: yes
	use-caps-for-id: yes
	cache-min-ttl: 0
	cache-max-ttl: 0
	cache-max-negative-ttl: 0
	neg-cache-size: 0
	prefetch: no
	unwanted-reply-threshold: 10000
	do-not-query-localhost: yes
	val-clean-additional: yes
	harden-algo-downgrade: yes
	auto-trust-anchor-file: "` + filepath.Join(os.TempDir(), "letsdebug_unbound_root.key") + `"
`

const unboundRootKey = `
; autotrust trust anchor file
;;id: . 1
;;last_queried: 1500518597 ;;Wed Jul 19 19:43:17 2017
;;last_success: 1500518597 ;;Wed Jul 19 19:43:17 2017
;;next_probe_time: 1500522140 ;;Wed Jul 19 20:42:20 2017
;;query_failed: 0
;;query_interval: 3600
;;retry_time: 3600
.	172800	IN	DNSKEY	257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU= ;{id = 20326 (ksk), size = 2048b} ;;state=1 [ ADDPEND ] ;;count=250 ;;lastchange=1499776649 ;;Tue Jul 11 05:37:29 2017
. 172800 IN DNSKEY 257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpzW5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relSQageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0= ;{id = 19036 (ksk), size = 2048b} ;;state=2 [ VALID ] ;;count=0 ;;lastchange=1404118431 ;;Mon Jun 30 01:53:51 2014
`
