package ledger

import "testing"

func TestBalanced(t *testing.T) {
	l := New()
	a, b := l.Acquire("variant"), l.Acquire("enum")
	if !l.Release(a) || !l.Release(b) {
		t.Fatal("release failed")
	}
	if l.Outstanding() != 0 || l.Double() != 0 || l.Acquired() != 2 {
		t.Fatalf("outstanding %d double %d acquired %d", l.Outstanding(), l.Double(), l.Acquired())
	}
}

func TestDoubleAndOutstanding(t *testing.T) {
	l := New()
	a := l.Acquire("variant")
	l.Acquire("variant")
	l.Release(a)
	if l.Release(a) {
		t.Fatal("second release of the same token must report false")
	}
	if l.Double() != 1 || l.Outstanding() != 1 {
		t.Fatalf("double %d outstanding %d", l.Double(), l.Outstanding())
	}
	if l.OpenKinds()["variant"] != 1 {
		t.Fatalf("open kinds %v", l.OpenKinds())
	}
}

func TestLeakStaysOutstanding(t *testing.T) {
	l := New()
	a := l.Acquire("array")
	l.Leak(a)
	if l.Leaked() != 1 || l.Outstanding() != 1 {
		t.Fatalf("leaked %d outstanding %d", l.Leaked(), l.Outstanding())
	}
}
