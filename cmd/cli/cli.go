package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/alexzorin/letsdebug"
)

func main() {
	var domain string
	var validationMethod string

	flag.StringVar(&domain, "domain", "example.org", "What domain to check")
	flag.StringVar(&validationMethod, "method", "http-01", "Which validation method to assume (http-01,dns-01)")
	flag.Parse()

	probs, err := letsdebug.Check(domain, letsdebug.ValidationMethod(validationMethod))
	if err != nil {
		fmt.Fprintf(os.Stderr, "A fatal error was experienced: %s", err)
		os.Exit(1)
	}

	if len(probs) == 0 {
		fmt.Println("All OK!")
		return
	}

	for _, prob := range probs {
		fmt.Printf("%s\nPROBLEM:\n  %s\n\nSEVERITY:\n  %s\n\nEXPLANATION:\n  %s\n\nDETAIL:\n  %s\n%s\n",
			strings.Repeat("-", 50), prob.Name, prob.Severity, prob.Explanation, prob.Detail, strings.Repeat("-", 50))
	}
}
