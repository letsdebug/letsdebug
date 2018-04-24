// Package letsdebug provides an library, web API and CLI to provide diagnostic
// information for why a particular (FQDN, ACME Validation Method) pair *may* fail
// when attempting to issue an SSL Certificate from Let's Encrypt (https://letsencrypt.org).
//
// The usage cannot be generalized to other ACME providers, as the policies checked by this package
// are specific to Let's Encrypt, rather than being mandated by the ACME protocol.
//
// This package relies on libunbound.
package letsdebug

import "fmt"

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
		if checkerProbs, err := checker.Check(ctx, domain, method); err == nil {
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
