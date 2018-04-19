// Package letsdebug provides an library, web API and CLI to provide diagnostic
// information for why a particular (FQDN, ACME Validation Method) pair *may* fail
// when attempting to issue an SSL Certificate from Let's Encrypt (https://letsencrypt.org).
//
// The usage cannot be generalized to other ACME providers, as the policies checked by this package
// are specific to Let's Encrypt, rather than being mandated by the ACME protocol.
//
// This package relies on libunbound.
package letsdebug

// Check will run each checker against the domain and validation method provided.
// It is expected that this method may take a long time to execute, and may not be cancelled.
func Check(domain string, method ValidationMethod) ([]Problem, error) {
	ctx := newScanContext()

	domain = normalizeFqdn(domain)

	probs := []Problem{}
	for _, checker := range checkers {
		if checkerProbs, err := checker.Check(ctx, domain, method); err == nil {
			probs = append(probs, checkerProbs...)
		} else if err != errNotApplicable {
			return nil, err
		}
	}
	return probs, nil
}
