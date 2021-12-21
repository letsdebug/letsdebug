package letsdebug

import (
	"crypto/rand"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/weppos/publicsuffix-go/publicsuffix"
)

// wildcardDNS01OnlyChecker ensures that a wildcard domain is only validated via dns-01.
type wildcardDNS01OnlyChecker struct{}

func (c wildcardDNS01OnlyChecker) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	if !strings.HasPrefix(domain, "*.") {
		return nil, errNotApplicable
	}

	if method == DNS01 {
		return nil, errNotApplicable
	}

	return []Problem{wildcardHTTP01(domain, method)}, nil
}

func wildcardHTTP01(domain string, method ValidationMethod) Problem {
	return Problem{
		Name:        "MethodNotSuitable",
		Explanation: fmt.Sprintf("A wildcard domain like %s can only be issued using a dns-01 validation method.", domain),
		Detail:      fmt.Sprintf("Invalid method: %s", method),
		Severity:    SeverityFatal,
	}
}

// txtRecordChecker ensures there is no resolution errors with the _acme-challenge txt record
type txtRecordChecker struct{}

func (c txtRecordChecker) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	if method != DNS01 {
		return nil, errNotApplicable
	}

	domain = strings.TrimPrefix(domain, "*.")

	if _, err := ctx.Lookup("_acme-challenge."+domain, dns.TypeTXT); err != nil {
		// report this problem as a fatal problem as that is the purpose of this checker
		return []Problem{txtRecordError(domain, err)}, nil
	}

	return nil, nil
}

func txtRecordError(domain string, err error) Problem {
	return Problem{
		Name: "TXTRecordError",
		Explanation: fmt.Sprintf(`An error occurred while attempting to lookup the TXT record on _acme-challenge.%s . `+
			`Any resolver errors that the Let's Encrypt CA encounters on this record will cause certificate issuance to fail.`, domain),
		Detail:   err.Error(),
		Severity: SeverityFatal,
	}
}

// txtDoubledLabelChecker ensures that a record for _acme-challenge.example.org.example.org
// wasn't accidentally created
type txtDoubledLabelChecker struct{}

func (c txtDoubledLabelChecker) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	if method != DNS01 {
		return nil, errNotApplicable
	}

	registeredDomain, _ := publicsuffix.Domain(domain)

	variants := []string{
		fmt.Sprintf("_acme-challenge.%s.%s", domain, domain),           // _acme-challenge.www.example.org.www.example.org
		fmt.Sprintf("_acme-challenge.%s.%s", domain, registeredDomain), // _acme-challenge.www.example.org.example.org
	}

	var found []string
	distinctCombined := map[string]struct{}{}
	var randomCombined string

	var foundMu sync.Mutex

	var wg sync.WaitGroup
	wg.Add(len(variants) + 1)

	doQuery := func(q string) ([]string, string) {
		found := []string{}
		combined := []string{}
		rrs, _ := ctx.Lookup(q, dns.TypeTXT)
		for _, rr := range rrs {
			txt, ok := rr.(*dns.TXT)
			if !ok {
				continue
			}
			found = append(found, txt.String())
			combined = append(combined, txt.Txt...)
		}
		sort.Strings(combined)
		return found, strings.Join(combined, "\n")
	}

	// Check the double label variants
	for _, variant := range variants {
		go func(q string) {
			defer wg.Done()

			values, combined := doQuery(q)
			if len(values) == 0 {
				return
			}

			foundMu.Lock()
			defer foundMu.Unlock()

			found = append(found, values...)
			distinctCombined[combined] = struct{}{}
		}(variant)
	}

	// Check the response for a random subdomain, to detect the presence of a wildcard TXT record
	go func() {
		defer wg.Done()

		nonce := make([]byte, 4)
		_, _ = rand.Read(nonce)
		_, randomCombined = doQuery(fmt.Sprintf("_acme-challenge.%s.%s", fmt.Sprintf("rand-%x", nonce), domain))
	}()

	wg.Wait()

	// If a randomized subdomain has the exact same non-empty TXT response as any of the "double labels", then
	// we are probably dealing with a wildcard TXT record in the zone, and it is probably not a meaningful
	// misconfiguration. In this case, say nothing.
	if _, ok := distinctCombined[randomCombined]; ok && randomCombined != "" {
		return nil, nil
	}

	if len(found) > 0 {
		return []Problem{{
			Name: "TXTDoubleLabel",
			Explanation: "Some DNS records were found that indicate TXT records may have been incorrectly manually entered into " +
				`DNS editor interfaces. The correct way to enter these records is to either remove the domain from the label (so ` +
				`enter "_acme-challenge.www.example.org" as "_acme-challenge.www") or include a period (.) at the ` +
				`end of the label (enter "_acme-challenge.example.org.").`,
			Detail:   fmt.Sprintf("The following probably-erroneous TXT records were found:\n%s", strings.Join(found, "\n")),
			Severity: SeverityWarning,
		}}, nil
	}

	return nil, nil
}

// nameServerOutOfSyncChecker checks the nameservers for the domain to check if any existing TXT records mismatch
// The general flow of this function is as follows,
// 1. Lookup the nameservers for the given domain
// 2. Lookup all the ips for those name servers
// 3. Query each of those nameservers' ips for the _acme-challenge subdomain txt record
// 4. Check all the txt records to see if they match
type nameServerOutOfSyncChecker struct{}

func (c nameServerOutOfSyncChecker) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	// txt entries only really matter for dns methods
	if method != DNS01 {
		return nil, errNotApplicable
	}

	// lookup name servers for domain
	nameSeverRRs, err := ctx.Lookup(domain, dns.TypeNS)
	if err != nil {
		return []Problem{dnsLookupFailed(domain, dns.TypeToString[dns.TypeNS], err)}, nil
	}

	// if no nameservers are returned, show a debug error
	// this is most likely a temporary issue, so don't show a warning/error
	if len(nameSeverRRs) <= 0 {
		return []Problem{
			debugProblem("NSOutOfSync",
				"No nameservers found",
				"No name server records were returned for the domain: "+domain),
		}, nil
	}

	// then grab all the ip addresses (both 4 and 6) for the name servers
	type nameServerIP struct {
		Hostname string
		IPs      []string
		Error    error
	}
	chanNSIP := make(chan nameServerIP)
	var wg sync.WaitGroup
	rrTypes := []uint16{dns.TypeA, dns.TypeAAAA}
	count := len(rrTypes) + len(nameSeverRRs)
	wg.Add(count)
	go func() {
		wg.Wait()
		close(chanNSIP)
	}()

	// async func to lookup given rr type on nameserver rr
	lookupNameServerAsync := func(rr dns.RR, rrType uint16) {
		defer wg.Done()

		ns := nameServerIP{}

		rrNS, ok := rr.(*dns.NS)
		if !ok {
			ns.Error = fmt.Errorf("Resource record returned is not a nameserver, got: %v", rr.String())
			chanNSIP <- ns
			return
		}

		ns.Hostname = rrNS.Ns

		rrs, err := ctx.Lookup(rrNS.Ns, rrType)
		if err != nil {
			ns.Error = fmt.Errorf("Error looking up %s %s: %v", rrNS.Ns, dns.TypeToString[dns.TypeTXT], err)
			chanNSIP <- ns
			return
		}

		for _, rr := range rrs {
			switch rrr := rr.(type) {
			case *dns.A:
				ns.IPs = append(ns.IPs, rrr.A.String())
			case *dns.AAAA:
				ns.IPs = append(ns.IPs, rrr.AAAA.String())
			default:
				ns.Error = fmt.Errorf("Unknown type returned from NS lookup %s %s: %s", rrNS.Ns, dns.TypeToString[rrType], dns.TypeToString[rr.Header().Rrtype])
				chanNSIP <- ns
				return
			}
		}
		chanNSIP <- ns
	}

	for _, rrType := range rrTypes {
		for _, rr := range nameSeverRRs {
			go lookupNameServerAsync(rr, rrType)
		}
	}

	type nameServer struct {
		// name server hostname
		Hostname string
		// name server ips
		IPs []string
		// mapping of ip to records for domain
		Records map[string][]string
	}
	// mapping of name server hostname to struct containing ips etc
	nameServers := map[string]*nameServer{}
	for nsIP := range chanNSIP {
		if nsIP.Error != nil {
			return []Problem{
				debugProblem("NSOutOfSync", "Error querying name server record", nsIP.Error.Error()),
			}, nil
		}
		ns := nameServers[nsIP.Hostname]
		if ns == nil {
			ns = &nameServer{Hostname: nsIP.Hostname}
			nameServers[nsIP.Hostname] = ns
		}
		ns.IPs = append(ns.IPs, nsIP.IPs...)
	}

	// grab all the ips for the fqdn for each name server
	type nameServerRecord struct {
		NSHostname string
		NSAddress  string
		Host       string
		Records    []string
		Error      error
	}
	chanNSRec := make(chan nameServerRecord)
	count = 0
	for _, v := range nameServers {
		count += len(v.IPs)
	}
	wg.Add(count)
	go func() {
		wg.Wait()
		close(chanNSRec)
	}()

	lookupDNSClient := func(host, server string) (*dns.Msg, error) {
		dnsClient := new(dns.Client)
		dnsClient.Timeout = 10 * time.Second
		dnsClient.Dialer = &net.Dialer{Timeout: dnsClient.Timeout}
		m := new(dns.Msg)
		m.SetQuestion(host, dns.TypeTXT)
		m.RecursionDesired = true
		r, _, err := dnsClient.Exchange(m, net.JoinHostPort(server, "53"))
		return r, err
	}

	// async function to look up a txt record using a given nameserver
	lookupTXTAsync := func(host, nsAddress, nsHostname string) {
		nsr := nameServerRecord{
			NSHostname: nsHostname,
			NSAddress:  nsAddress,
			Host:       host,
		}

		r, err := lookupDNSClient(host, nsAddress)
		if err != nil {
			nsr.Error = err
			chanNSRec <- nsr
			wg.Done()
			return
		}
		if r.Rcode != dns.RcodeSuccess {
			nsr.Error = fmt.Errorf("Invalid rcode: %s", dns.RcodeToString[r.Rcode])
			chanNSRec <- nsr
			wg.Done()
			return
		}
		for _, ans := range r.Answer {
			switch v := ans.(type) {
			case *dns.TXT:
				nsr.Records = append(nsr.Records, v.Txt...)
			case *dns.CNAME:
				// TODO: add support for following CNAME records?
				nsr.Error = fmt.Errorf("You are currently using an CNAME record on %q -> %q. This service does not support recursive CNAME queries.",
					host, v.Target)
			default:
				nsr.Error = fmt.Errorf("Invalid rrtype: %s", dns.TypeToString[v.Header().Rrtype])
			}
		}
		chanNSRec <- nsr
		wg.Done()
	}

	fqdnHost := "_acme-challenge." + domain + "."
	for _, ns := range nameServers {
		for _, ip := range ns.IPs {
			go lookupTXTAsync(fqdnHost, ip, ns.Hostname)
		}
	}

	for nsRec := range chanNSRec {
		if nsRec.Error != nil {
			return []Problem{
				debugProblem("NSOutOfSync",
					"Error querying name server record for text record", nsRec.Error.Error()),
			}, nil
		}
		ns := nameServers[nsRec.NSHostname]
		if ns == nil {
			return []Problem{
				debugProblem("NSOutOfSync",
					"Unknown nameserver hostname returned", nsRec.NSHostname),
			}, nil
		}
		if ns.Records == nil {
			ns.Records = map[string][]string{}
		}
		if _, ok := ns.Records[nsRec.NSAddress]; ok {
			return []Problem{
				debugProblem("NSOutOfSync",
					"Duplicate IP returned for nameserver", nsRec.NSHostname),
			}, nil
		}
		ns.Records[nsRec.NSAddress] = append(ns.Records[nsRec.NSAddress], nsRec.Records...)
	}

	// check the returned records
	var lastNameServer *nameServer
	var nameServerList []string
	actuallyHasRecords := false
	for _, ns := range nameServers {
		nameServerList = append(nameServerList, fmt.Sprintf("%s (%s)", ns.Hostname, strings.Join(ns.IPs, ",")))

		if lastNameServer == nil {
			lastNameServer = ns
			continue
		}

		var lastIP string
		var lastRecords []string
		for ip, recs := range ns.Records {
			if lastIP == "" {
				goto fauxContinue
			}

			if !actuallyHasRecords && len(recs) > 0 {
				actuallyHasRecords = true
			}

			if !sliceContainsSameValues(lastRecords, recs) {
				return []Problem{
					{
						Name:        "NSOutOfSync",
						Explanation: "Name servers have different TXT records",
						Detail: fmt.Sprintf("Name server %s (records: %s) has different records to %s (records: %s)",
							lastIP, strings.Join(lastRecords, ", "), ip, strings.Join(recs, ", ")),
						Severity: SeverityWarning,
					},
				}, nil
			}

		fauxContinue:
			lastIP = ip
			lastRecords = recs
		}
	}

	if !actuallyHasRecords {
		return []Problem{
			debugProblem("NSOutOfSync", "No TXT records for _acme-challenge",
				fmt.Sprintf("No listed nameservers on the domain %q have any TXT records for the _acme-challenge subdomain."+
					"\nThis is not necessarily a problem as it could mean the acme client you are using to issue certificates is cleaning up after challenges, but may be worth noting if you are unable to issue certificates."+
					"\nNameserver list:\n - %s",
					domain, strings.Join(nameServerList, "\n - "))),
		}, nil
	}

	return nil, nil
}

// This is not efficient and mutates the slices
// TODO: use something better for this comparison
func sliceContainsSameValues(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 {
		return true
	}

	sort.Strings(a)
	sort.Strings(b)

	for i, v := range a {
		if b[i] != v {
			return false
		}
	}

	return true
}
