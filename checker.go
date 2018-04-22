package letsdebug

import (
	"errors"
	"sync"
)

// ValidationMethod represents an ACME validation method
type ValidationMethod string

const (
	HTTP01   ValidationMethod = "http-01"    // HTTP01 represents the ACME http-01 validation method.
	DNS01    ValidationMethod = "dns-01"     // DNS01 represents the ACME dns-01 validation method.
	TLSSNI01 ValidationMethod = "tls-sni-01" // TLSSNI01 represents the ACME tls-sni-01 validation method.
	TLSSNI02 ValidationMethod = "tls-sni-02" // TLSSNI02 represents the ACME tls-sni-02 validation method.
)

var (
	ValidMethods     = map[ValidationMethod]bool{HTTP01: true, DNS01: true, TLSSNI01: true, TLSSNI02: true}
	errNotApplicable = errors.New("Checker not applicable for this domain and method")
	checkers         []checker
)

func init() {
	checkers = []checker{
		// show stopping checkers
		validDomainChecker{},
		tlssni0102DisabledChecker{},
		wildcardDns01OnlyChecker{},
		caaChecker{},

		// others
		dnsAChecker{},
		httpAccessibilityChecker{},
	}
}

type checker interface {
	Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error)
}

// asyncCheckerBlock represents a checker which is composed of other checkers that can be run simultaneously.
type asyncCheckerBlock []checker

func (c asyncCheckerBlock) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	// waitgroup for all the checker goroutines
	var wg sync.WaitGroup
	wg.Add(len(c))

	// error channel which either
	// - signals either the waitgroup is done (nil error)
	// - signals a checker has encountered an error (shortcut other checkers)
	errChan := make(chan error, len(c))

	go func() {
		wg.Wait()
		errChan <- nil
	}()

	// channel to which any problems encountered in each checker are written
	resultsChan := make(chan []Problem, len(c))

	// launch each goroutine
	for _, currentChecker := range c {
		go func(chk checker) {
			defer wg.Done()
			probs, err := chk.Check(ctx, domain, method)
			if err != nil {
				errChan <- err
				return
			}
			resultsChan <- probs
		}(currentChecker)
	}

	var probs []Problem

	select {
	case checkerProbs := <-resultsChan:
		// store any results
		if len(checkerProbs) > 0 {
			probs = append(probs, checkerProbs...)
		}

	case err := <-errChan:
		// short circuit exit
		return probs, err
	}

	return probs, nil
}
