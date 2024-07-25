# Let's Debug

[![Build Status](https://travis-ci.org/letsdebug/letsdebug.svg?branch=master)](https://travis-ci.org/letsdebug/letsdebug)
[![godoc](https://godoc.org/github.com/letsdebug/letsdebug?status.svg)](https://godoc.org/github.com/letsdebug/letsdebug)

Let's Debug is a diagnostic website, API, CLI and Go package for quickly and accurately finding and reporting issues for any domain that may prevent issuance of a Let's Encrypt SSL certificate for any ACME validation method.

It is motivated by [this community thread](https://community.letsencrypt.org/t/creating-a-webservice-for-analysis-of-common-problems/45836).

## Status
Currently [deployed to letsdebug.net and regularly in use](https://letsdebug.net).

## Problems Detected

| Name                                                                 | Description                                                                                                                                                                                                                                                   | Examples                        |
|----------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------|
| InvalidMethod, ValidationMethodDisabled, ValidationMethodNotSuitable | Checks the ACME validation method is valid and usable for the provided domain name.                                                                                                                                                                           | [Example](./screenshots/1.png)  |
| InvalidDomain                                                        | Checks the domain is a valid domain name on a public TLD.                                                                                                                                                                                                     | [Example](./screenshots/2.png)  |
| StatusNotOperational                                                 | Checks that the Let's Encrypt service is not experiencing an outage, according to status.io                                                                                                                                                                   | -                               |
| DNSLookupFailed, TXTRecordError                                      | Checks that the Unbound resolver (via libunbound) is able to resolve a variety records relevant to Let's Encrypt. Discovers problems such as DNSSEC issues, 0x20 mixed case randomization, timeouts etc, in the spirit of jsha's unboundtest.com              | [Example](./screenshots/3.png)  |
| CAAIssuanceNotAllowed                                                | Checks that no CAA records are preventing the issuance of Let's Encrypt certificates.                                                                                                                                                                         | [Example](./screenshots/4.png)  |
| CAACriticalUnknown                                                   | Checks that no CAA critical flags unknown to Let's Encrypt are used                                                                                                                                                                                           | -                               |
| RateLimit                                                            | Checks that the domain name is not currently affected by any of the domain-based rate limits imposed by Let's Encrypt, using the public certwatch Postgres interface from Comodo's crt.sh.                                                                    | [Example](./screenshots/5.png)  |
| NoRecords, ReservedAddress                                           | Checks that sufficient valid A/AAAA records are present to perform HTTP-01 validation                                                                                                                                                                         | [Example](./screenshots/6.png)  |
| BadRedirect                                                          | Checks that no bad HTTP redirects are present. Discovers redirects that aren't accessible, unacceptable ports, unacceptable schemes, accidental missing trailing slash on redirect.                                                                           | [Example](./screenshots/7.png)  |
| WebserverMisconfiguration                                            | Checks whether the server is serving the wrong protocol on the wrong port as the result of an HTTP-01 validation request.                                                                                                                                     | -                               |
| ANotWorking, AAAANotWorking                                          | Checks whether listed IP addresses are not functioning properly for HTTP-01 validation, including timeouts and other classes of network and HTTP errors.                                                                                                      | [Example](./screenshots/8.png)  |
| MultipleIPAddressDiscrepancy                                         | For domains with multiple A/AAAA records, checks whether there are major discrepancies between the server responses to reveal when the addresses may be pointing to different servers accidentally.                                                           | [Example](./screenshots/9.png)  |
| CloudflareCDN                                                        | Checks whether the domain is being served via Cloudflare's proxy service (and therefore SSL termination is occurring at Cloudflare)                                                                                                                           | -                               |
| CloudflareSSLNotProvisioned                                          | Checks whether the domain has its SSL terminated by Cloudflare and Cloudflare has not provisioned a certificate yet (leading to a TLS handshake error).                                                                                                       | [Example](./screenshots/10.png) |
| IssueFromLetsEncrypt                                                 | Attempts to detect issues with a high degree of accuracy via the Let's Encrypt v2 staging service by attempting to perform an authorization for the domain. Discovers issues such as CA-based domain blacklists & other policies, specific networking issues. | [Example](./screenshots/11.png) |
| TXTDoubleLabel                                                       | Checks for the presence of records that are doubled up (e.g. `_acme-challenge.example.org.example.org`). Usually indicates that the user has been incorrectly creating records in their DNS user interface.                                                   | [Example](./screenshots/12.png) |
| PortForwarding                                                       | Checks whether the domain is serving a modem-router administrative interface instead of an intended webserver, which is indicative of a port-forwarding misconfiguration.                                                                                     | [Example](./screenshots/13.png) |
| SanctionedDomain                                                     | Checks whether the Registered Domain is present on the [USG OFAC SDN List](https://sanctionssearch.ofac.treas.gov/). Updated daily.                                                                                                                           | [Example](./screenshots/14.png) |
| BlockedByNginxTestCookie                                             | Checks whether the HTTP-01 validation requests are being intercepted by [testcookie-nginx-module](https://github.com/kyprizel/testcookie-nginx-module).                                                                                                       | [Example](./screenshots/15.png) |
| HttpOnHttpsPort                                                      | Checks whether the server reported receiving an HTTP request on an HTTPS-only port                                                                                                                                                                            | [Example](./screenshots/16.png) |
| BlockedByFirewall                                                    | Checks whether HTTP-01 validation requests are being blocked by Palo Alto firewall devices                                                                                                                                                                    | [Example](./screenshots/17.png) |
| UnexpectedHttpResponse                                               | Checks whether HTTP-01 validation requests are being answered with unusual HTTP response codes                                                                                                                                                                | [Example](./screenshots/18.png) |

## Web API Usage

There is a JSON-based API available as part of the web frontend.

### Submitting a test

```bash
$ curl --data '{"method":"http-01","domain":"example.com"}' -H 'content-type: application/json' https://letsdebug.net
```
```javascript
{"Domain":"example.com","ID":674477}
```

### Submitting a test with custom options

```bash
curl --data '{"method":"http-01","domain":"example.com","options":{"http_request_path":"custom-path","http_expect_response":"abc123"}}' -H 'content-type: application/json' https://letsdebug.net
```

Available options are as follows:

| Option | Description |
-------|-------------|
`http_request_path` | What path within `/.well-known/acme-challenge/` to use instead of `letsdebug-test` (default) for the HTTP check. Max length 255. |
`http_expect_response` | What exact response to expect from each server during the HTTP check. By default, no particular response is expected. If present and the response does not match, the test will fail with an Error severity. It is highly recommended to always use a completely random value. Max length 255. |

### Viewing tests

```bash
$ curl -H 'accept: application/json' https://letsdebug.net/example.com/674477
```
```javascript
{"id":674477,"domain":"example.com","method":"http-01","status":"Complete","created_at":"2021-09-08T04:02:26.416259Z","started_at":"2021-09-08T04:02:26.419336Z","completed_at":"2021-09-08T04:02:30.529766Z","result":{}}
```

or to view all recent tests

```bash
$ curl -H 'accept: application/json' https://letsdebug.net/example.com
```

### Performing a query against the Certwatch database

```bash
$ curl "https://letsdebug.net/certwatch-query?q=<urlencoded SQL query>"
```
```javascript
{
  "query": "select c.id as crtsh_id, x509_subjectName(c.CERTIFICATE), x509_notAfter(c.CERTIFICATE) from certificate c where x509_notAfter(c.CERTIFICATE) = '2018-06-01 16:25:44' AND x509_issuerName(c.CERTIFICATE) LIKE 'C=US, O=Let''s Encrypt%';",
  "results": [
    {
      "crtsh_id": 346300797,
      "x509_notafter": "2018-06-01T16:25:44Z",
      "x509_subjectname": "CN=hivdatingzimbabwe.com"
    },
    /* ... */
  ]
}
```

## CLI Usage

You can download binaries for tagged releases for Linux for both the CLi and the server [from the releases page](https://github.com/letsdebug/letsdebug/releases). 


    letsdebug-cli -domain example.org -method http-01 -debug

## Library Usage

```go

import "github.com/letsdebug/letsdebug"

problems, _ := letsdebug.Check("example.org", letsdebug.HTTP01)
```

## Installation

### Dependencies

This package relies on a fairly recent version of libunbound.

* On Debian-based distributions:

    `apt install libunbound8 libunbound-dev`

* On EL-based distributions, you may need to build from source because the packages are ancient on e.g. CentOS, but you can try:

    `yum install unbound-libs unbound-devel`

* On OSX, [Homebrew](https://brew.sh/) contains the latest version of unbound:

    `brew install unbound`

You will also need Go's [dep](https://github.com/golang/dep) dependency manager.

### Releases
You can save time by [downloading tagged releases for 64-bit Linux](https://github.com/letsdebug/letsdebug/releases). Keep in mind you will still need to have libunbound present on your system.

### Building

    go get -u github.com/letsdebug/letsdebug/...
    cd $GOPATH/src/github.com/letsdebug/letsdebug
    make clean letsdebug-cli letsdebug-server


## Contributing
Any contributions containing JavaScript will be discarded, but other feedback, bug reports, suggestions and enhancements are welcome - please open an issue first.

## LICENSE

See [LICENSE](LICENSE)