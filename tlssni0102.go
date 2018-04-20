package letsdebug

import (
	"fmt"
)

// tlssni0102Checker checks whether the validation method is tls-sni-01/02 and returns a fatal error.
type tlssni0102Checker struct {
}

func validationDisabled(method ValidationMethod, url string) Problem {
	return Problem{
		Name: "ValidationMethodDisabled",
		Explanation: fmt.Sprintf(`The validation method provided (%s) has been disabled by Let's Encrypt. `+
			`For more information, please visit the url in the details.`, method),
		Detail:   url,
		Priority: PriorityFatal,
	}
}

func (c tlssni0102Checker) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	if method != TLSSNI01 && method != TLSSNI02 {
		return nil, errNotApplicable
	}

	prob := validationDisabled(method,
		"https://community.letsencrypt.org/t/important-what-you-need-to-know-about-tls-sni-validation-issues/50811")

	return []Problem{prob}, nil
}
