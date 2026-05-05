//go:build linux

package letsdebug

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/miekg/unbound"
)

var (
	_unboundInstance *unbound.Unbound
	_unboundOnce     sync.Once
)

func getUnbound() *unbound.Unbound {
	_unboundOnce.Do(func() {
		_unboundInstance = unbound.New()
		if err := setUnboundConfig(_unboundInstance); err != nil {
			log.Fatalf("failed to configure Unbound resolver: %v", err)
		}
	})
	return _unboundInstance
}

// UnboundResolver uses libunbound via github.com/miekg/unbound.
type UnboundResolver struct {
	// no fields for now
}

func defaultResolver() Resolver {
	return &UnboundResolver{}
}

func (u *UnboundResolver) Lookup(name string, rrType uint16, timeout time.Duration) (*LookupResult, error) {
	// reuse the existing pattern: run resolve in a goroutine and respect timeout
	type resWrap struct {
		res *unbound.Result
		err error
	}

	ch := make(chan resWrap, 1)
	go func() {
		r, err := getUnbound().Resolve(name, rrType, dns.ClassINET)
		ch <- resWrap{r, err}
	}()

	select {
	case rr := <-ch:
		if rr.err != nil {
			return nil, rr.err
		}
		if rr.res == nil {
			return nil, nil
		}
		out := &LookupResult{
			RRs:      rr.res.Rr,
			Rcode:    rr.res.Rcode,
			Bogus:    rr.res.Bogus,
			WhyBogus: rr.res.WhyBogus,
			NxDomain: rr.res.NxDomain,
		}
		return out, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("DNS response for %s/%s could not be resolved within the timeout. This may indicate slow or unresponsive nameservers", name, dns.TypeToString[rrType])
	}
}

// setUnboundConfig is unchanged from the previous implementation and still
// lives here because it configures the libunbound instance.
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
		if err := ub.SetOption(opt.Opt, opt.Val); err != nil {
			return fmt.Errorf("failed to configure unbound with option %s %v", opt.Opt, err)
		}
	}

	if err := ub.SetOption("use-caps-for-id:", "yes"); err != nil {
		if err = ub.SetOption("use-caps-for-id", "yes"); err != nil {
			return fmt.Errorf("failed to configure unbound with use-caps-for-id: %v", err)
		}
	}

	return ub.AddTa(`.                       1428    IN      DNSKEY  257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3 +/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kv ArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF 0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+e oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfd RUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwN R1AkUTV74bU=
.                       1428    IN      DNSKEY  256 3 8 AwEAAdSiy6sslYrcZSGcuMEK4DtE8DZZY1A08kAsviAD49tocYO5m37A vIOyzeiKBWuPuJ4m9u5HonCM/ntxklZKYFyMftv8XoRwbiXdpSjfdpNH iMYTTV2oDUNMjdLFnF6HYSY48xrPbevQOYbAFGHpxqcXAQT0+BaBiAx3 Ls6lXBQ3/hSVOprvDWJCQiI2OT+9+saKLddSIX6DwTVy0S5T4YY4EGg5 R3c/eKUb2/8XgKWUzlOIZsVAZZUSTKW0tX54ccAALO7Grvsx/NW62jc1 xv6wWAXocOEVgB7+4Lzb7q9p5o30+sYoGpOsKgFvMSy4oCZTQMQx2Sjd /NG2bMMw6nM=
.                       1428    IN      RRSIG   DNSKEY 8 0 172800 20240910000000 20240820000000 20326 . cnf+5CdVZorlsu872+Q5X6mDWQlof//t+AlVDG21XH07xGy6X5imUIRa Jf3XKqJ95fJC0GmyvI0XxjJpSEmNphaO5BK7zjlNMoDv2Y3ppfWHc7xh T1sOoqy1StVgfkNULSrrEsnZmUOCPEomJJ5H4iBMfzOlrbpRABMeA2TV HeJO8Q/SOFy4dqHxX3S+4nd/GVc0gR+QOejczqzJ6k5GDgpP3zpb9Sa6 UZs6bJ/fvaj1Yisb3cren6t6OwdsWbIj6qlfCGcUienTvjaNsq8IySUg YOiw0w+HUw9vHfKVe96SjXwTaBcomOmXPjrIEW4Dq0j1iUAVxWMkPure eGdpsg==`)
}
