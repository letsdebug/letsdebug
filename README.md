# Let's Debug

Let's Debug is a diagnostic website, API, CLI and Go package for quickly and accurately finding and reporting issues for any domain that may prevent issuance of a Let's Encrypt SSL certificate for any ACME validation method.

It is motivated by [this community thread](https://community.letsencrypt.org/t/creating-a-webservice-for-analysis-of-common-problems/45836).

## Status/Progress
Not yet usable.

[Track the MVP milstone](https://github.com/alexzorin/letsdebug/milestone/1).

## Problems Detected

| Name | Description | Examples
-------|-------------|--------|
| InvalidMethod, ValidationMethodDisabled, ValidationMethodNotSuitable | Checks the ACME validation method is valid and usable for the provided domain name. | - |
| InvalidDomain | Checks the domain is a valid domain name on a public TLD. | - |
| StatusNotOperational| Checks that the Let's Encrypt service is not experiencing an outage, according to status.io | - 
| DNSLookupFailed, TXTRecordError | Checks that the Unbound resolver (via libunbound) is able to resolve a variety records relevant to Let's Encrypt. Discovers problems such as DNSSEC issues, 0x20 mixed case randomization, timeouts etc, in the spirit of jsha's unboundtest.com | - |
CAAIssuanceNotAllowed | Checks that no CAA records are preventing the issuance of Let's Encrypt certificates. | - |
CAACriticalUnknown | Checks that no CAA critical flags unknown to Let's Encrypt are used | - |
RateLimit | Checks that the domain name is not currently affected by any of the domain-based rate limits imposed by Let's Encrypt, using the public certwatch Postgres interface from Comodo's crt.sh. | - |
NoRecords, ReservedAddress | Checks that sufficient valid A/AAAA records are present to perform HTTP-01 validation | - |
BadRedirect | Checks that no bad HTTP redirects are present. Discovers redirects that aren't accessible, unacceptable ports, unacceptable schemes, accidental missing trailing slash on redirect. | - |
WebserverMisconfiguration | Checks whether the server is serving the wrong protocol on the wrong port as the result of an HTTP-01 validation request. | - |
ANotWorking, AAAANotWorking | Checks whether listed IP addresses are not functioning properly for HTTP-01 validation, including timeouts and other classes of network and HTTP errors. | - |
CloudflareCDN | Checks whether the domain is being served via Cloudflare's proxy service (and therefore SSL termination is occuring at Cloudflare) | - |
CloudflareSSLNotProvisioned | Checks whether the domain has its SSL terminated by Cloudflare and Cloudflare has not provisioned a certificate yet (leading to a TLS handshake error). | - |
IssueFromLetsEncrypt | Attempts to detect issues with a high degree of accuracy via the Let's Encrypt v2 staging service by attempting to perform an authorization for the domain. Discovers issues such as CA-based domain blacklists & other policies, specific networking issues. | - |

## Installation

### Dependencies

This package relies on a fairly recent version of libunbound.

On Debian-based distributions:

    apt-install libunbound2 libunbound-dev

On EL-based distributions, you may need to build from source because the packages are ancient on e.g. CentOS, but you can try:

    yum install unbound-libs unbound-devel

You will also need Go's `dep`.

### Building

    go get -u github.com/alexzorin/letsdebug/...
    cd $GOPATH/src/github.com/alexzorin/letsdebug
    dep ensure
    LETSDEBUG_DEBUG=1 go run cmd/cli/cli.go -domain example.org -method http-01

## Contributing
TBD.

## LICENSE
TBD.