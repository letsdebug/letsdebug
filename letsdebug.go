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
	"reflect"
)

// Check will run each checker against the domain and validation method provided.
// It is expected that this method may take a long time to execute, and may not be cancelled.
func Check(domain string, method ValidationMethod) ([]Problem, error) {
	ctx := newScanContext()

	domain = normalizeFqdn(domain)

	var probs []Problem
	for _, checker := range checkers {
		// run the pre-flight for the current checker
		if err := checker.PreFlight(ctx, domain, method); err != nil {
			if err == errNotApplicable {
				continue
			}
			return probs, err
		}

		// run the check for the current checker
		checkerProbs, err := checker.Check(ctx, domain, method)
		if err != nil {
			// TODO: reflect name is hacky, should probably have a `Name() string` method in the interface
			// maybe a Description() too? might be useful for listing available checkers and enabling/disabling specific ones
			return probs, fmt.Errorf("Error running checker %s, %v", reflect.TypeOf(checker).Name(), err)
		}

		probs = append(probs, checkerProbs...)

		// dont continue checking when a fatal error occurs
		for _, p := range checkerProbs {
			if p.Severity == SeverityFatal {
				return probs, nil
			}
		}
	}
	return probs, nil
}
