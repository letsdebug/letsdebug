package letsdebug

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"io/ioutil"
	"net"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/eggsampler/acme"

	"fmt"

	"net/http"

	"time"

	"encoding/json"

	// Driver for crtwatch/ratelimitChecker
	_ "github.com/lib/pq"
	"github.com/miekg/dns"
	"github.com/weppos/publicsuffix-go/net/publicsuffix"
	psl "github.com/weppos/publicsuffix-go/publicsuffix"
)

// validMethodChecker ensures that the provided authorization method is valid and supported.
type validMethodChecker struct{}

func (c validMethodChecker) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	if validMethods[method] {
		return nil, errNotApplicable
	}

	return []Problem{notValidMethod(method)}, nil
}

func notValidMethod(method ValidationMethod) Problem {
	var supportedMethods []string
	for k := range validMethods {
		supportedMethods = append(supportedMethods, string(k))
	}
	return Problem{
		Name:        "InvalidMethod",
		Explanation: fmt.Sprintf(`"%s" is not a supported validation method.`, method),
		Detail:      fmt.Sprintf("Supported methods: %s", strings.Join(supportedMethods, ", ")),
		Severity:    SeverityFatal,
	}
}

// validDomainChecker ensures that the FQDN is well-formed and is part of a public suffix.
type validDomainChecker struct{}

func (c validDomainChecker) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	var probs []Problem

	if strings.HasPrefix(domain, "*.") {
		domain = domain[2:]
	}

	for _, ch := range []byte(domain) {
		if (('a' <= ch && ch <= 'z') ||
			('A' <= ch && ch <= 'A') ||
			('0' <= ch && ch <= '9') ||
			ch == '.' || ch == '-') == false {
			probs = append(probs, invalidDomain(domain, fmt.Sprintf("Invalid character present: %c", ch)))
			return probs, nil
		}
	}

	if len(domain) > 230 {
		probs = append(probs, invalidDomain(domain, "Domain too long"))
		return probs, nil
	}

	if ip := net.ParseIP(domain); ip != nil {
		probs = append(probs, invalidDomain(domain, "Domain is an IP address"))
		return probs, nil
	}

	rule := psl.DefaultList.Find(domain, &psl.FindOptions{IgnorePrivate: true, DefaultRule: nil})
	if rule == nil {
		probs = append(probs, invalidDomain(domain, "Domain doesn't end in a public TLD"))
		return probs, nil
	}

	if r := rule.Decompose(domain)[1]; r == "" {
		probs = append(probs, invalidDomain(domain, "Domain is a TLD"))
		return probs, nil
	} else {
		probs = append(probs, debugProblem("PublicSuffix", "The IANA public suffix is the TLD of the Registered Domain",
			fmt.Sprintf("The TLD for %s is: %s", domain, r)))
	}

	return probs, nil
}

// caaChecker ensures that any caa record on the domain, or up the domain tree, allow issuance for letsencrypt.org
type caaChecker struct{}

func (c caaChecker) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	var probs []Problem

	wildcard := false
	if strings.HasPrefix(domain, "*.") {
		wildcard = true
		domain = domain[2:]
	}

	rrs, err := ctx.Lookup(domain, dns.TypeCAA)
	if err != nil {
		probs = append(probs, dnsLookupFailed(domain, "CAA", err))
		return probs, nil
	}

	// check any found caa records
	if len(rrs) > 0 {
		var issue []*dns.CAA
		var issuewild []*dns.CAA
		var criticalUnknown []*dns.CAA

		for _, rr := range rrs {
			caaRr, ok := rr.(*dns.CAA)
			if !ok {
				continue
			}

			switch caaRr.Tag {
			case "issue":
				issue = append(issue, caaRr)
			case "issuewild":
				issuewild = append(issuewild, caaRr)
			default:
				if caaRr.Flag == 1 {
					criticalUnknown = append(criticalUnknown, caaRr)
				}
			}
		}

		probs = append(probs, debugProblem("CAA",
			"CAA records control authorization for certificate authorities to issue certificates for a domain",
			collateRecords(append(issue, issuewild...))))

		if len(criticalUnknown) > 0 {
			probs = append(probs, caaCriticalUnknown(domain, wildcard, criticalUnknown))
			return probs, nil
		}

		if len(issue) == 0 && !wildcard {
			return probs, nil
		}

		records := issue
		if wildcard && len(issuewild) > 0 {
			records = issuewild
		}

		for _, r := range records {
			if extractIssuerDomain(r.Value) == "letsencrypt.org" {
				return probs, nil
			}
		}

		probs = append(probs, caaIssuanceNotAllowed(domain, wildcard, records))
		return probs, nil
	}

	// recurse up to the public suffix domain until a caa record is found
	// a.b.c.com -> b.c.com -> c.com until
	if ps, _ := publicsuffix.PublicSuffix(domain); domain != ps && ps != "" {
		splitDomain := strings.SplitN(domain, ".", 2)

		parentProbs, err := c.Check(ctx, splitDomain[1], method)
		if err != nil {
			return nil, fmt.Errorf("error checking caa record on domain: %s, %v", splitDomain[1], err)
		}

		probs = append(probs, parentProbs...)
	}

	return probs, nil
}

func extractIssuerDomain(value string) string {
	// record can be:
	// issuedomain.tld; someparams
	return strings.Trim(strings.SplitN(value, ";", 2)[0], " \t")
}

func collateRecords(records []*dns.CAA) string {
	var s []string
	for _, r := range records {
		s = append(s, r.String())
	}
	return strings.Join(s, "\n")
}

func caaCriticalUnknown(domain string, wildcard bool, records []*dns.CAA) Problem {
	return Problem{
		Name: "CAACriticalUnknown",
		Explanation: fmt.Sprintf(`CAA record(s) exist on %s (wildcard=%t) that are marked as critical but are unknown to Let's Encrypt. `+
			`These record(s) as shown in the detail must be removed, or marked as non-critical, before a certificate can be issued by the Let's Encrypt CA.`, domain, wildcard),
		Detail:   collateRecords(records),
		Severity: SeverityFatal,
	}
}

func caaIssuanceNotAllowed(domain string, wildcard bool, records []*dns.CAA) Problem {
	return Problem{
		Name: "CAAIssuanceNotAllowed",
		Explanation: fmt.Sprintf(`No CAA record on %s (wildcard=%t) contains the issuance domain "letsencrypt.org". `+
			`You must either add an additional record to include "letsencrypt.org" or remove every existing CAA record. `+
			`A list of the CAA records are provided in the details.`, domain, wildcard),
		Detail:   collateRecords(records),
		Severity: SeverityFatal,
	}
}

func invalidDomain(domain, reason string) Problem {
	return Problem{
		Name:        "InvalidDomain",
		Explanation: fmt.Sprintf(`"%s" is not a valid domain name that Let's Encrypt would be able to issue a certificate for.`, domain),
		Detail:      reason,
		Severity:    SeverityFatal,
	}
}

// cloudflareChecker determines if the domain is using cloudflare, and whether a certificate has been provisioned by cloudflare yet.
type cloudflareChecker struct{}

func (c cloudflareChecker) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	var probs []Problem

	if strings.HasPrefix(domain, "*.") {
		domain = domain[2:]
	}

	cl := http.Client{
		Timeout: httpTimeout * time.Second,
	}
	resp, err := cl.Get("https://" + domain)
	if err == nil { // no tls error, cert must be issued
		// check if it's cloudflare
		if hasCloudflareHeader(resp.Header) {
			probs = append(probs, cloudflareCDN(domain))
		}

		return probs, nil
	}

	// disable redirects
	cl.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// attempt to connect over http with redirects disabled to check cloudflare header
	resp, err = cl.Get("http://" + domain)
	if err != nil {
		return probs, nil
	}

	if hasCloudflareHeader(resp.Header) {
		probs = append(probs, cloudflareCDN(domain))
		probs = append(probs, cloudflareSslNotProvisioned(domain))
	}

	return probs, nil
}

func hasCloudflareHeader(h http.Header) bool {
	return strings.Contains(strings.ToLower(h.Get("server")), "cloudflare")
}

func cloudflareCDN(domain string) Problem {
	return Problem{
		Name: "CloudflareCDN",
		Explanation: fmt.Sprintf(`The domain %s is being served through Cloudflare CDN. Any Let's Encrypt certificate installed on the `+
			`origin server will only encrypt traffic between the server and Cloudflare. It is strongly recommended that the SSL option 'Full SSL (strict)' `+
			`be enabled.`, domain),
		Detail:   "https://support.cloudflare.com/hc/en-us/articles/200170416-What-do-the-SSL-options-mean-",
		Severity: SeverityWarning,
	}
}

func cloudflareSslNotProvisioned(domain string) Problem {
	return Problem{
		Name:        "CloudflareSSLNotProvisioned",
		Explanation: fmt.Sprintf(`The domain %s is being served through Cloudflare CDN and a certificate has not yet been provisioned yet by Cloudflare.`, domain),
		Detail:      "https://support.cloudflare.com/hc/en-us/articles/203045244-How-long-does-it-take-for-Cloudflare-s-SSL-to-activate-",
		Severity:    SeverityWarning,
	}
}

// statusioChecker ensures there is no reported operational problem with the Let's Encrypt service via the status.io public api.
type statusioChecker struct{}

func (c statusioChecker) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	var probs []Problem

	resp, err := http.Get("https://api.status.io/1.0/status/55957a99e800baa4470002da")
	if err != nil {
		// some connectivity errors with status.io is probably not worth reporting
		return probs, nil
	}
	defer resp.Body.Close()

	statusioApiResp := struct {
		Result struct {
			StatusOverall struct {
				Updated    time.Time `json:"updated"`
				Status     string    `json:"status"`
				StatusCode int       `json:"status_code"`
			} `json:"status_overall"`
		} `json:"result"`
	}{}

	if err := json.NewDecoder(resp.Body).Decode(&statusioApiResp); err != nil {
		return probs, fmt.Errorf("error decoding status.io api response: %v", err)
	}

	if statusioApiResp.Result.StatusOverall.StatusCode != 100 {
		probs = append(probs, statusioNotOperational(statusioApiResp.Result.StatusOverall.Status, statusioApiResp.Result.StatusOverall.Updated))
	}

	probs = append(probs, debugProblem("StatusIO", "The current status.io status for Let's Encrypt",
		fmt.Sprintf("%v", statusioApiResp.Result.StatusOverall.Status)))

	return probs, nil
}

func statusioNotOperational(status string, updated time.Time) Problem {
	return Problem{
		Name: "StatusNotOperational",
		Explanation: fmt.Sprintf(`The current status as reported by the Let's Encrypt status page is %s as at %v. `+
			`Depending on the reported problem, this may affect certificate issuance. For more information, please visit the status page.`, status, updated),
		Detail:   "https://letsencrypt.status.io/",
		Severity: SeverityWarning,
	}
}

type crtList map[string]*x509.Certificate

// FindCommonPSLCertificates finds any certificates which contain any DNSName
// that shares the Registered Domain `registeredDomain`.
func (l crtList) FindWithCommonRegisteredDomain(registeredDomain string) []*x509.Certificate {
	var out []*x509.Certificate

	for _, cert := range l {
		for _, name := range cert.DNSNames {
			if nameRegDomain, _ := publicsuffix.EffectiveTLDPlusOne(name); nameRegDomain == registeredDomain {
				out = append(out, cert)
				break
			}
		}
	}

	return out
}

func (l crtList) GetOldestCertificate() *x509.Certificate {
	var oldest *x509.Certificate
	for _, crt := range l {
		if oldest == nil || crt.NotBefore.Before(oldest.NotBefore) {
			oldest = crt
		}
	}
	return oldest
}

// CountDuplicates counts how many duplicate certificates there are
// that also contain the name `domain`
func (l crtList) CountDuplicates(domain string) map[string]int {
	counts := map[string]int{}

	for _, cert := range l {
		found := false
		for _, name := range cert.DNSNames {
			if name == domain {
				found = true
				break
			}
		}
		if !found {
			continue
		}
		names := make([]string, len(cert.DNSNames))
		copy(names, cert.DNSNames)
		sort.Strings(names)
		k := strings.Join(names, ",")
		counts[k]++
	}

	return counts
}

// rateLimitChecker ensures that the domain is not currently affected
// by domain-based rate limits using crtwatch's database
type rateLimitChecker struct {
}

const rateLimitCheckerQuery = `SELECT c.CERTIFICATE der
FROM certificate c
WHERE c.ID IN (
	SELECT DISTINCT ci.CERTIFICATE_ID FROM certificate_identity ci
	WHERE reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower($1))
	AND ci.name_type = 'dNSName'
	AND ci.ISSUER_CA_ID IN (16418)
)
AND x509_notBefore(c.CERTIFICATE) >= $2
ORDER BY x509_notBefore(c.CERTIFICATE) DESC
OFFSET 0 LIMIT 100;
`

// Pointer receiver because we're keeping state across runs
func (c *rateLimitChecker) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	if os.Getenv("LETSDEBUG_DISABLE_CERTWATCH") != "" {
		return nil, errNotApplicable
	}

	if strings.HasPrefix(domain, "*.") {
		domain = domain[2:]
	}

	db, err := sql.Open("postgres", "user=guest dbname=certwatch host=crt.sh sslmode=disable connect_timeout=5")
	if err != nil {
		return []Problem{
			internalProblem(fmt.Sprintf("Failed to connect to certwatch database to check rate limits: %v", err), SeverityWarning),
		}, nil
	}
	defer db.Close()

	// Since we are checking rate limits, we need to query the Registered Domain
	// for the domain in question
	registeredDomain, _ := publicsuffix.EffectiveTLDPlusOne(domain)

	timeoutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rows, err := db.QueryContext(timeoutCtx, rateLimitCheckerQuery, "%"+registeredDomain, time.Now().Add(-7*24*time.Hour))
	if err != nil && err != sql.ErrNoRows {
		return []Problem{
			internalProblem(fmt.Sprintf("Failed to query certwatch database to check rate limits: %v", err), SeverityWarning),
		}, nil
	}

	probs := []Problem{}

	// Read in the DER-encoded certificates
	certs := crtList{}
	var certBytes []byte
	for rows.Next() {
		if err := rows.Scan(&certBytes); err != nil {
			probs = append(probs, internalProblem(fmt.Sprintf("Failed to query certwatch database while checking rate limits: %v", err), SeverityWarning))
			break
		}
		crt, err := x509.ParseCertificate(certBytes)
		if err != nil {
			probs = append(probs, internalProblem(fmt.Sprintf("Failed to parse certificate while checking rate limits: %v", err), SeverityWarning))
			continue
		}
		certs[crt.SerialNumber.String()] = crt
	}
	if err := rows.Err(); err != nil {
		return []Problem{
			internalProblem(fmt.Sprintf("Failed to query certwatch database to check rate limits: %v", err), SeverityWarning),
		}, nil
	}

	var debug string

	// Limit: Certificates per Registered Domain
	// TODO: implement Renewal Excemption
	certsTowardsRateLimit := certs.FindWithCommonRegisteredDomain(registeredDomain)
	if len(certs) > 0 && len(certsTowardsRateLimit) >= 20 {
		dropOff := certs.GetOldestCertificate().NotBefore.Add(7 * 24 * time.Hour)
		dropOffDiff := dropOff.Sub(time.Now()).Truncate(time.Minute)

		probs = append(probs, rateLimited(domain, fmt.Sprintf("The 'Certificates per Registered Domain' limit ("+
			"20 certificates per week that share the same Registered Domain: %s) has been exceeded. "+
			"There is no way to work around this rate limit. "+
			"The next non-renewal certificate for this Registered Domain should be issuable after %v (%v from now).",
			registeredDomain, dropOff, dropOffDiff)))
	}

	for _, cert := range certsTowardsRateLimit {
		debug = fmt.Sprintf("%s\nSerial: %s\nNotBefore: %v\nNames: %v\n", debug, cert.SerialNumber.String(), cert.NotBefore, cert.DNSNames)
	}

	// Limit: Duplicate Certificate limit of 5 certificates per week
	for names, dupes := range certs.CountDuplicates(domain) {
		if dupes < 5 {
			continue
		}
		probs = append(probs, rateLimited(domain,
			fmt.Sprintf(`The Duplicate Certificate limit (5 certificates with the exact same set of domains per week) has been `+
				`exceeded and is affecting the domain "%s". The exact set of domains affected is: "%v". It may be possible to avoid this `+
				`rate limit by issuing a certificate with an additional or different domain name.`, domain, names)))
	}

	if debug != "" {
		probs = append(probs, debugProblem("RateLimit", "Certificates contributing to rate limits for this domain", debug))
	}

	return probs, nil
}

func rateLimited(domain, detail string) Problem {
	registeredDomain, _ := publicsuffix.EffectiveTLDPlusOne(domain)
	return Problem{
		Name: "RateLimit",
		Explanation: fmt.Sprintf(`%s is currently affected by Let's Encrypt-based rate limits (https://letsencrypt.org/docs/rate-limits/). `+
			`You may review certificates that have already been issued by visiting https://crt.sh/?q=%%%s . `+
			`Please note that it is not possible to ask for a rate limit to be manually cleared.`, domain, registeredDomain),
		Detail:   detail,
		Severity: SeverityError,
	}
}

// acmeStagingChecker tries to create an authorization on
// Let's Encrypt's staging server and parse the error urn
// to see if there's anything interesting reported.
type acmeStagingChecker struct {
	client   acme.AcmeClient
	account  acme.AcmeAccount
	clientMu sync.Mutex
}

func (c *acmeStagingChecker) buildAcmeClient() error {
	cl, err := acme.NewClient("https://acme-staging-v02.api.letsencrypt.org/directory")
	if err != nil {
		return err
	}

	regrPath := os.Getenv("LETSDEBUG_ACMESTAGING_ACCOUNTFILE")
	if regrPath == "" {
		regrPath = "acme-account.json"
	}
	buf, err := ioutil.ReadFile(regrPath)
	if err != nil {
		return err
	}

	var out struct {
		PEM string `json:"pem"`
		URL string `json:"url"`
	}
	if err := json.Unmarshal(buf, &out); err != nil {
		return err
	}

	block, _ := pem.Decode([]byte(out.PEM))
	pk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	c.account = acme.AcmeAccount{PrivateKey: pk, Url: out.URL}
	c.client = cl

	return nil
}

func (c *acmeStagingChecker) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	if os.Getenv("LETSDEBUG_DISABLE_ACMESTAGING") != "" {
		return nil, errNotApplicable
	}

	c.clientMu.Lock()
	if c.account.PrivateKey == nil {
		if err := c.buildAcmeClient(); err != nil {
			c.clientMu.Unlock()
			return []Problem{
				internalProblem(fmt.Sprintf("Couldn't setup Let's Encrypt staging checker, skipping: %v", err), SeverityWarning),
			}, nil
		}
	}
	c.clientMu.Unlock()

	probs := []Problem{}

	order, err := c.client.NewOrder(c.account, []acme.AcmeIdentifier{acme.AcmeIdentifier{Type: "dns", Value: domain}})
	if err != nil {
		if p := translateAcmeError(domain, err); p.Name != "" {
			probs = append(probs, p)
		}
		probs = append(probs, debugProblem("LetsEncryptStaging", "Order creation error", err.Error()))
		return probs, nil
	}

	var wg sync.WaitGroup
	wg.Add(len(order.Authorizations))
	var probsMu sync.Mutex

	unhandledError := func(err error) {
		probsMu.Lock()
		defer probsMu.Unlock()

		probs = append(probs, internalProblem("An unknown problem occured while performing a test "+
			"authorization against the Let's Encrypt staging service: "+err.Error(), SeverityWarning))
	}

	authzFailures := []string{}

	for _, authzURL := range order.Authorizations {
		go func(authzURL string) {
			defer wg.Done()

			authz, err := c.client.FetchAuthorization(c.account, authzURL)
			if err != nil {
				unhandledError(err)
				return
			}

			chal, ok := authz.ChallengeMap[string(method)]
			if !ok {
				unhandledError(fmt.Errorf("Missing challenge method (want %v): %v", method, authz.ChallengeMap))
				return
			}

			if _, err := c.client.UpdateChallenge(c.account, chal); err != nil {
				probsMu.Lock()
				if p := translateAcmeError(domain, err); p.Name != "" {
					probs = append(probs, p)
				}
				authzFailures = append(authzFailures, err.Error())
				probsMu.Unlock()
			}
		}(authzURL)
	}

	wg.Wait()

	if len(authzFailures) > 0 {
		probs = append(probs, debugProblem("LetsEncryptStaging",
			fmt.Sprintf("Challenge update failures for %s in order %s", domain, order.Url),
			strings.Join(authzFailures, "\n")))
	} else {
		probs = append(probs, debugProblem("LetsEncryptStaging", "Order for "+domain, order.Url))
	}

	return probs, nil
}

func translateAcmeError(domain string, err error) Problem {
	if acmeErr, ok := err.(acme.AcmeError); ok {
		urn := strings.TrimPrefix(acmeErr.Type, "urn:ietf:params:acme:error:")
		switch urn {
		case "rejectedIdentifier", "unknownHost", "rateLimited", "caa":
			return letsencryptProblem(domain, acmeErr.Detail, SeverityError)
		// When something bad is happening on staging
		case "serverInternal":
			return letsencryptProblem(domain,
				fmt.Sprintf(`There may be internal issues on the staging service: %v`, acmeErr.Detail), SeverityWarning)
		// Unauthorized is what we expect, except for these exceptions that we should handle:
		// - When VA OR RA is checking Google Safe Browsing (groan)
		case "unauthorized":
			if strings.Contains(acmeErr.Detail, "considered an unsafe domain") {
				return letsencryptProblem(domain, acmeErr.Detail, SeverityError)
			}
			return Problem{}
		default:
			return Problem{}
		}
	}
	return internalProblem(fmt.Sprintf("An unknown issue occured when performing a test authorization "+
		"against the Let's Encrypt staging service: %v", err), SeverityWarning)
}

func letsencryptProblem(domain, detail string, severity SeverityLevel) Problem {
	return Problem{
		Name: "IssueFromLetsEncrypt",
		Explanation: fmt.Sprintf(`A test authorization for %s to the Let's Encrypt staging service has revealed `+
			`issues that may prevent any certificate for this domain being issued.`, domain),
		Detail:   detail,
		Severity: severity,
	}
}
