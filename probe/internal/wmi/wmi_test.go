package wmi

import (
	"errors"
	"testing"
)

// Portable helpers only; the real-WMI tests are behind the wmiintegration tag.

func TestItoa(t *testing.T) {
	for n, want := range map[int]string{0: "0", 7: "7", 1234567: "1234567"} {
		if got := itoa(n); got != want {
			t.Errorf("itoa(%d) = %q", n, got)
		}
	}
}

func TestErrInfoPlainError(t *testing.T) {
	ei := errInfo("ExecQuery", errors.New("boom"))
	if ei.Op != "ExecQuery" || ei.HR != 0 || ei.Text != "boom" {
		t.Fatalf("%+v", ei)
	}
	if errInfo("x", nil) != nil {
		t.Fatal("nil error produced info")
	}
}

func TestPartialKeepsFirst(t *testing.T) {
	var r Result
	partial(&r, &ErrInfo{Op: "a"})
	partial(&r, &ErrInfo{Op: "b"})
	if r.Err.Op != "a" || r.Status != "" {
		t.Fatalf("%+v", r)
	}
}
