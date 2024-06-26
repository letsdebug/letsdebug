package letsdebug

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	httpTimeout = 10
)

type redirectError string

func (e redirectError) Error() string {
	return string(e)
}

type httpCheckResult struct {
	StatusCode        int
	ServerHeader      string
	IP                net.IP
	InitialStatusCode int
	NumRedirects      int
	FirstDial         time.Time
	DialStack         []string
	Content           []byte
}

func (r *httpCheckResult) Trace(s string) {
	if r.FirstDial.IsZero() {
		r.FirstDial = time.Now()
	}
	r.DialStack = append(r.DialStack,
		fmt.Sprintf("@%dms: %s", time.Since(r.FirstDial).Nanoseconds()/1e6, s))
}

func (r httpCheckResult) IsZero() bool {
	return r.StatusCode == 0
}

func (r httpCheckResult) String() string {
	addrType := "IPv6"
	if r.IP.To4() != nil {
		addrType = "IPv4"
	}

	lines := []string{
		"Address=" + r.IP.String(),
		"Address Type=" + addrType,
		"Server=" + r.ServerHeader,
		"HTTP Status=" + strconv.Itoa(r.InitialStatusCode),
	}
	if r.NumRedirects > 0 {
		lines = append(lines, "Number of Redirects="+strconv.Itoa(r.NumRedirects))
		lines = append(lines, "Final HTTP Status="+strconv.Itoa(r.StatusCode))
	}

	return fmt.Sprintf("[%s]", strings.Join(lines, ","))
}

type checkHTTPTransport struct {
	transport http.RoundTripper
	result    *httpCheckResult
}

func (t checkHTTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.transport.RoundTrip(req)

	if t.result != nil && err != nil {
		t.result.Trace(fmt.Sprintf("Experienced error: %v", err))
	}

	if t.result != nil && resp != nil {
		if t.result.InitialStatusCode == 0 {
			t.result.InitialStatusCode = resp.StatusCode
		}

		t.result.Trace(fmt.Sprintf("Server response: HTTP %s", resp.Status))
	}

	return resp, err
}

func makeSingleShotHTTPTransport() *http.Transport {
	return &http.Transport{
		// Boulder VA's HTTP transport settings
		// https://github.com/letsencrypt/boulder/blob/387e94407c58fe0ff65207a89304776ee7417410/va/http.go#L143-L160
		DisableKeepAlives:   true,
		IdleConnTimeout:     time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConns:        1,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
}

func checkHTTP(scanCtx *scanContext, domain string, address net.IP) (httpCheckResult, Problem) {
	dialer := net.Dialer{
		Timeout: httpTimeout * time.Second,
	}

	checkRes := &httpCheckResult{
		IP:        address,
		DialStack: []string{},
	}

	var redirErr redirectError

	baseHTTPTransport := makeSingleShotHTTPTransport()
	baseHTTPTransport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, _ := net.SplitHostPort(addr)
		host = normalizeFqdn(host)

		dialFunc := func(ip net.IP, port string) (net.Conn, error) {
			checkRes.Trace(fmt.Sprintf("Dialing %s", ip.String()))
			if ip.To4() == nil {
				return dialer.DialContext(ctx, "tcp", "["+ip.String()+"]:"+port)
			}
			return dialer.DialContext(ctx, "tcp", ip.String()+":"+port)
		}

		// Only override the address for this specific domain.
		// We don't want to mangle redirects.
		if host == domain {
			return dialFunc(address, port)
		}

		// For other hosts, we need to use Unbound to resolve the name
		otherAddr, err := scanCtx.LookupRandomHTTPRecord(host)
		if err != nil {
			return nil, err
		}

		return dialFunc(otherAddr, port)
	}

	cl := http.Client{
		Transport: checkHTTPTransport{
			result:    checkRes,
			transport: baseHTTPTransport,
		},
		// boulder: va.go fetchHTTP
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			checkRes.NumRedirects++

			if len(via) >= 10 {
				redirErr = redirectError(fmt.Sprintf("Too many (%d) redirects, last redirect was to: %s", len(via), req.URL.String()))
				return redirErr
			}

			checkRes.Trace(fmt.Sprintf("Received redirect to %s", req.URL.String()))

			host := req.URL.Host
			if _, p, err := net.SplitHostPort(host); err == nil {
				if port, _ := strconv.Atoi(p); port != 80 && port != 443 {
					redirErr = redirectError(fmt.Sprintf("Bad port number provided when fetching %s: %s", req.URL.String(), p))
					return redirErr
				}
			}

			scheme := strings.ToLower(req.URL.Scheme)
			if scheme != "http" && scheme != "https" {
				redirErr = redirectError(fmt.Sprintf("Bad scheme provided when fetching %s: %s", req.URL.String(), scheme))
				return redirErr
			}

			// Also check for domain.tld.well-known/acme-challenge
			if strings.HasSuffix(req.URL.Hostname(), ".well-known") {
				redirErr = redirectError(fmt.Sprintf("It appears that a redirect was generated by your web server that is missing a trailing "+
					"slash after your domain name: %v. Check your web server configuration and .htaccess for Redirect/RedirectMatch/RewriteRule.",
					req.URL.String()))
				return redirErr
			}

			return nil
		},
	}

	reqURL := "http://" + domain + "/.well-known/acme-challenge/" + scanCtx.httpRequestPath
	checkRes.Trace(fmt.Sprintf("Making a request to %s (using initial IP %s)", reqURL, address))

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return *checkRes, internalProblem(fmt.Sprintf("Failed to construct validation request: %v", err), SeverityError)
	}

	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Let's Debug emulating Let's Encrypt validation server; +https://letsdebug.net)")

	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout*time.Second)
	defer cancel()

	req = req.WithContext(ctx)

	resp, err := cl.Do(req)
	if resp != nil {
		checkRes.StatusCode = resp.StatusCode
		checkRes.ServerHeader = resp.Header.Get("Server")
	}
	if err != nil {
		if redirErr != "" {
			err = redirErr
		}
		return *checkRes, translateHTTPError(domain, address, err, checkRes.DialStack)
	}

	defer resp.Body.Close()

	maxLen := 8192
	if l := len(scanCtx.httpExpectResponse) + 2; l > maxLen {
		maxLen = l
	}
	r := io.LimitReader(resp.Body, int64(maxLen))

	buf, err := io.ReadAll(r)
	checkRes.Content = buf

	// If we expect a certain response, check for it
	if scanCtx.httpExpectResponse != "" {
		if err != nil {
			return *checkRes, translateHTTPError(domain, address,
				fmt.Errorf(`This test expected the server to respond with "%s" but instead we experienced an error reading the response: %v`,
					scanCtx.httpExpectResponse, err),
				checkRes.DialStack)
		} else if respStr := string(buf); respStr != scanCtx.httpExpectResponse {
			return *checkRes, translateHTTPError(domain, address,
				fmt.Errorf(`This test expected the server to respond with "%s" but instead we got a response beginning with "%s"`,
					scanCtx.httpExpectResponse, respStr),
				checkRes.DialStack)
		}
	} else {
		if err == nil {
			// By default, assume 404/2xx are ok. Warn on others.
			if (checkRes.StatusCode > 299 || checkRes.StatusCode < 200) && checkRes.StatusCode != 404 {
				return *checkRes, unexpectedHttpResponse(domain, resp.Status, string(checkRes.Content), checkRes.DialStack)
			}
		} else {
			return *checkRes, translateHTTPError(domain, address,
				fmt.Errorf(`we experienced an error reading the response: %v`, err),
				checkRes.DialStack)
		}
	}

	return *checkRes, Problem{}
}

func translateHTTPError(domain string, address net.IP, e error, dialStack []string) Problem {
	if redirErr, ok := e.(redirectError); ok {
		return badRedirect(domain, redirErr, dialStack)
	}

	if strings.HasSuffix(e.Error(), "http: server gave HTTP response to HTTPS client") {
		return httpServerMisconfiguration(domain, "Web server is serving the wrong protocol on the wrong port: "+e.Error()+
			". This may be due to a previous HTTP redirect rather than a webserver misconfiguration.\n\nTrace:\n"+strings.Join(dialStack, "\n"))
	}

	// Make a nicer error message if it was a context timeout
	if urlErr, ok := e.(*url.Error); ok && urlErr.Timeout() {
		e = fmt.Errorf("A timeout was experienced while communicating with %s/%s: %v",
			domain, address.String(), urlErr)
	}

	if address.To4() == nil {
		return aaaaNotWorking(domain, address.String(), e, dialStack)
	} else {
		return aNotWorking(domain, address.String(), e, dialStack)
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

func aaaaNotWorking(domain, ipv6Address string, err error, dialStack []string) Problem {
	return Problem{
		Name: "AAAANotWorking",
		Explanation: fmt.Sprintf(`%s has an AAAA (IPv6) record (%s) but a test request to this address over port 80 did not succeed. `+
			`Your web server must have at least one working IPv4 or IPv6 address. `+
			`You should either ensure that validation requests to this domain succeed over IPv6, or remove its AAAA record.`,
			domain, ipv6Address),
		Detail:   fmt.Sprintf("%s\n\nTrace:\n%s", err.Error(), strings.Join(dialStack, "\n")),
		Severity: SeverityError,
	}
}

func aNotWorking(domain, addr string, err error, dialStack []string) Problem {
	return Problem{
		Name: "ANotWorking",
		Explanation: fmt.Sprintf(`%s has an A (IPv4) record (%s) but a request to this address over port 80 did not succeed. `+
			`Your web server must have at least one working IPv4 or IPv6 address.`,
			domain, addr),
		Detail:   fmt.Sprintf("%s\n\nTrace:\n%s", err.Error(), strings.Join(dialStack, "\n")),
		Severity: SeverityError,
	}
}

func badRedirect(domain string, err error, dialStack []string) Problem {
	return Problem{
		Name: "BadRedirect",
		Explanation: fmt.Sprintf(`Sending an ACME HTTP validation request to %s results in an unacceptable redirect. `+
			`This is most likely a misconfiguration of your web server or your web application.`,
			domain),
		Detail:   fmt.Sprintf("%s\n\nTrace:\n%s", err.Error(), strings.Join(dialStack, "\n")),
		Severity: SeverityError,
	}
}

func unexpectedHttpResponse(domain string, httpStatus string, httpBody string, dialStack []string) Problem {
	return Problem{
		Name:        "UnexpectedHttpResponse",
		Explanation: fmt.Sprintf(`Sending an ACME HTTP validation request to %s results in unexpected HTTP response %s. This indicates that the webserver is misconfigured or misbehaving.`, domain, httpStatus),
		Detail:      fmt.Sprintf("%s\n\n%s\n\nTrace:\n%s", httpStatus, httpBody, strings.Join(dialStack, "\n")),
		Severity:    SeverityWarning,
	}
}
