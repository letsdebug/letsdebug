// Package letsdebug provides an library, web API and CLI to provide diagnostic
// information for why a particular (FQDN, ACME Validation Method) pair *may* fail
// when attempting to issue an SSL Certificate from Let's Encrypt (https://letsencrypt.org).
//
// The usage cannot be generalized to other ACME providers, as the policies checked by this package
// are specific to Let's Encrypt, rather than being mandated by the ACME protocol.
//
// This package relies on libunbound.
package letsdebug

import (
	"fmt"
	"os"
	"reflect"
	"time"
)

// Check will run each checker against the domain and validation method provided.
// It is expected that this method may take a long time to execute, and may not be cancelled.
func Check(domain string, method ValidationMethod) (probs []Problem, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("panic: %v", r)
		}
	}()

	ctx := newScanContext()

	domain = normalizeFqdn(domain)

	for _, checker := range checkers {
		t := reflect.TypeOf(checker)
		debug("[*] + %v\n", t)
		start := time.Now()
		checkerProbs, err := checker.Check(ctx, domain, method)
		debug("[*] - %v in %v\n", t, time.Now().Sub(start))
		if err == nil {
			if len(checkerProbs) > 0 {
				probs = append(probs, checkerProbs...)
			}
			// dont continue checking when a fatal error occurs
			if hasFatalProblem(probs) {
				break
			}
		} else if err != errNotApplicable {
			return nil, err
		}
	}
	return probs, nil
}

var isDebug *bool

func debug(format string, args ...interface{}) {
	if isDebug == nil {
		d := os.Getenv("LETSDEBUG_DEBUG") != ""
		isDebug = &d
	}
	if !(*isDebug) {
		return
	}
	fmt.Fprintf(os.Stderr, format, args...)
}
