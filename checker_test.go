package letsdebug

import (
	"errors"
	"testing"
)

type checkerFail struct{}

func (c checkerFail) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	return nil, errors.New("failure")
}

type checkerSucceedEmpty struct{}

func (c checkerSucceedEmpty) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	return nil, nil
}

type checkerSucceedWithProblem struct{}

func (c checkerSucceedWithProblem) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	return []Problem{{Name: "Empty"}}, nil
}

type checkerPanic struct{}

func (c checkerPanic) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	panic("hi")
}

func TestAsyncCheckerBlock_Check(t *testing.T) {
	// check success condition
	a := asyncCheckerBlock{
		checkerSucceedWithProblem{},
		checkerSucceedWithProblem{},
		checkerSucceedEmpty{},
	}
	probs, err := a.Check(nil, "", "")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(probs) != 2 {
		t.Fatalf("expected 2 problems, got: %d", len(probs))
	}

	// check fail condition
	a = asyncCheckerBlock{
		checkerFail{},
	}
	if _, err := a.Check(nil, "", ""); err == nil {
		t.Fatal("expected error, got none")
	}

	// check panic recovery
	a = asyncCheckerBlock{
		checkerPanic{},
	}
	if _, err := a.Check(nil, "", ""); err == nil {
		t.Fatal("expected error, got none")
	}
}
