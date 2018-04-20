package letsdebug

import "github.com/miekg/dns"

type lookupResult struct {
	RRs   []dns.RR
	Error error
}

type scanContext struct {
	rrs map[string]map[uint16]lookupResult
}

func newScanContext() *scanContext {
	return &scanContext{
		rrs: map[string]map[uint16]lookupResult{},
	}
}

func (sc *scanContext) Lookup(name string, rrType uint16) ([]dns.RR, error) {
	rrMap, ok := sc.rrs[name]
	if !ok {
		rrMap = map[uint16]lookupResult{}
		sc.rrs[name] = rrMap
	}

	if result, ok := rrMap[rrType]; ok {
		return result.RRs, result.Error
	}

	resolved, err := lookup(name, rrType)
	rrMap[rrType] = lookupResult{
		RRs:   resolved,
		Error: err,
	}

	return resolved, err
}
