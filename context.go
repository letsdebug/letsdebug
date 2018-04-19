package letsdebug

import "github.com/miekg/dns"

type scanContext struct {
	rrs map[string]map[uint16][]dns.RR
}

func newScanContext() *scanContext {
	return &scanContext{
		rrs: map[string]map[uint16][]dns.RR{},
	}
}

func (sc *scanContext) Lookup(name string, rrType uint16) ([]dns.RR, error) {
	rrMap, ok := sc.rrs[name]
	if !ok {
		rrMap = map[uint16][]dns.RR{}
		sc.rrs[name] = rrMap
	}

	if rrs, ok := rrMap[rrType]; ok {
		return rrs, nil
	}

	resolved, err := lookup(name, rrType)
	if err != nil {
		return nil, err
	}

	rrMap[rrType] = resolved
	return resolved, nil
}
