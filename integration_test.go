//go:build integration
// +build integration

package letsdebug

import "testing"

func TestAcmeStaging(t *testing.T) {
	checker := &acmeStagingChecker{}

	// Fails at order creation
	probs, err := checker.Check(nil, "paypal.com", HTTP01)
	if err != nil {
		t.Fatal(err)
	}
	if len(probs) != 1 || probs[0].Name != "IssueFromLetsEncrypt" {
		t.Fatalf("Should have got a single LE issue but got %v", probs)
	}

	// Fails at challenge update for an error we should report (domain is 127.0.0.1)
	probs, err = checker.Check(nil, "localtest.me", HTTP01)
	if err != nil {
		t.Fatal(err)
	}
	if len(probs) != 1 || probs[0].Name != "IssueFromLetsEncrypt" {
		t.Fatalf("Should have got a single LE issue but got %v", probs)
	}

	// Fails at challenge update but with a simple unauthorized error
	probs, err = checker.Check(nil, "fleetssl.com", HTTP01)
	if err != nil {
		t.Fatal(err)
	}
	if len(probs) != 0 {
		t.Fatalf("Got errors when we should have got none: %v", probs)
	}
}

func TestWildcards(t *testing.T) {
	checkers := []checker{
		validMethodChecker{},
		validDomainChecker{},
		wildcardDns01OnlyChecker{},
		caaChecker{},
		&rateLimitChecker{},
		dnsAChecker{},
		txtRecordChecker{},
		httpAccessibilityChecker{},
		cloudflareChecker{},
	}

	ctx := newScanContext()

	for _, checker := range checkers {
		probs, err := checker.Check(ctx, "*.wildcard-test.letsdebug.net", DNS01)
		if err != nil && err != errNotApplicable {
			t.Fatal(err)
		}

		if len(probs) > 0 {
			t.Fatalf("Expected no problems but got %v", probs)
		}
	}
}
