package clock

import (
	"testing"
	"time"
)

func TestResolutionIsFine(t *testing.T) {
	a := Now()
	b := Now()
	for b == a {
		b = Now()
	}
	if d := b.Sub(a); d <= 0 || d > 50*time.Microsecond {
		t.Fatalf("QPC step %v", d)
	}
}

func TestAgreesWithSleep(t *testing.T) {
	a := Now()
	time.Sleep(50 * time.Millisecond)
	if d := Since(a); d < 45*time.Millisecond || d > 500*time.Millisecond {
		t.Fatalf("50 ms sleep measured %v", d)
	}
}
