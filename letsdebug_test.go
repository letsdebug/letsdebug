package letsdebug

import "testing"

func TestCheck(t *testing.T) {
	// check success condition
	checkers = []checker{
		checkerSucceedWithProblem{},
		checkerSucceedWithProblem{},
		checkerSucceedEmpty{},
	}
	probs, err := Check("", "")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(probs) != 2 {
		t.Fatalf("expected 2 problems, got: %d", len(probs))
	}

	// check fail condition
	checkers = []checker{
		checkerFail{},
	}
	probs, err = Check("", "")
	if err == nil {
		t.Fatal("expected error, got none")
	}

	// check panic recovery
	checkers = []checker{
		checkerPanic{},
	}
	probs, err = Check("", "")
	if err == nil {
		t.Fatal("expected error, got none")
	}
}
