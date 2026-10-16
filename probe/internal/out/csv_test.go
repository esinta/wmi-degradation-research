package out

import (
	"compress/gzip"
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRotateAndGzip(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir, "q", []string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 10, 16, 10, 59, 59, 0, time.UTC)
	w.now = func() time.Time { return clock }
	if err := w.Write([]string{"1", "x"}); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(2 * time.Second) // next hour
	if err := w.Write([]string{"2", "y,z"}); err != nil {
		t.Fatal(err)
	}
	if err := w.Write([]string{"bad"}); err == nil {
		t.Fatal("wrong column count accepted")
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*"))
	if len(files) != 2 {
		t.Fatalf("files %v", files)
	}
	for i, hour := range []string{"20261016T10Z", "20261016T11Z"} {
		name := filepath.Join(dir, "q-"+hour+".csv.gz")
		f, err := os.Open(name)
		if err != nil {
			t.Fatal(err)
		}
		zr, err := gzip.NewReader(f)
		if err != nil {
			t.Fatal(err)
		}
		recs, err := csv.NewReader(zr).ReadAll()
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		if len(recs) != 2 || strings.Join(recs[0], ",") != "a,b" {
			t.Fatalf("%s: %v", hour, recs)
		}
		if want := []string{"1", "2"}[i]; recs[1][0] != want {
			t.Fatalf("%s: row %v", hour, recs[1])
		}
	}
	if w.Rows() != 2 {
		t.Fatalf("rows %d", w.Rows())
	}
}

func TestSet(t *testing.T) {
	s, err := NewSet(t.TempDir(), map[string][]string{"a": {"x"}, "b": {"y", "z"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.W("b").Write([]string{"1", "2"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}
