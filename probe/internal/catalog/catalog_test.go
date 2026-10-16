package catalog

import (
	"math"
	"strings"
	"testing"
)

// The per-namespace sums must match the measured Esinta rates on the Win10
// lab VM (design §1), so k is a true multiple of production.
func TestProductionRatesMatchMeasured(t *testing.T) {
	want := map[string]float64{
		NSCimv2: 420, NSSubscription: 60, NSDefender: 60, NSStandardCimv2: 48,
		NSTaskScheduler: 24, NSDeviceGuard: 12, NSVolumeEncrypt: 12, NSTpm: 12,
	}
	got := map[string]float64{}
	for _, q := range Production() {
		got[q.Namespace] += q.PerHour
	}
	for ns, w := range want {
		if math.Abs(got[ns]-w) > 1e-9 {
			t.Errorf("%s: %g/h, want %g/h", ns, got[ns], w)
		}
	}
	if len(got) != len(want) {
		t.Errorf("namespaces = %v", got)
	}
}

func TestKeysUniqueAndWQLShape(t *testing.T) {
	seen := map[string]bool{}
	for _, q := range Production() {
		if seen[q.Key] {
			t.Errorf("duplicate key %s", q.Key)
		}
		seen[q.Key] = true
		if !strings.HasPrefix(q.WQL, "SELECT ") {
			t.Errorf("%s: WQL %q", q.Key, q.WQL)
		}
		verbs := strings.Count(q.WQL, "%")
		switch q.Key {
		case "proc_pid", "evt_sec", "evt_sys":
			if verbs != 1 {
				t.Errorf("%s: want one format verb, got %d in %q", q.Key, verbs, q.WQL)
			}
		default:
			if verbs != 0 {
				t.Errorf("%s: unexpected %% in %q", q.Key, q.WQL)
			}
		}
		if (q.Truth == TruthKeySet || q.Truth == TruthProcSet || q.Truth == TruthServices || q.Truth == TruthDrivers) && q.KeyProp == "" {
			t.Errorf("%s: truth %v needs KeyProp", q.Key, q.Truth)
		}
	}
}

func TestStressOnlyReweights(t *testing.T) {
	p, s := Production(), Stress()
	if len(p) != len(s) {
		t.Fatal("stress changed the query set")
	}
	for i := range p {
		w := stressWeight[p[i].Key]
		if w == 0 {
			w = 1
		}
		if s[i].PerHour != p[i].PerHour*w {
			t.Errorf("%s: %g, want %g", p[i].Key, s[i].PerHour, p[i].PerHour*w)
		}
	}
}

func TestWithoutAndNamespaces(t *testing.T) {
	qs := Without(Production(), []string{`ROOT\CIMV2\Security\MicrosoftTpm`, NSDeviceGuard})
	for _, q := range qs {
		if q.Namespace == NSTpm || q.Namespace == NSDeviceGuard {
			t.Fatalf("%s not removed", q.Key)
		}
	}
	ns := Namespaces(qs)
	if ns[0] != NSCimv2 {
		t.Errorf("cimv2 not first: %v", ns)
	}
	if len(Production()) == len(qs) {
		t.Error("Without removed nothing")
	}
}
