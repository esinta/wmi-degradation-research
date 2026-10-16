// Package out writes the run's CSV files (design §6.1): hourly rotation, the
// closed file gzipped, a header in every file, flushed every second so a
// crash loses at most a second of rows.
package out

import (
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Writer is one rotating CSV stream (e.g. "queries").
type Writer struct {
	dir, base string
	header    []string
	now       func() time.Time

	mu     sync.Mutex
	f      *os.File
	bw     *bufio.Writer
	cw     *csv.Writer
	hour   time.Time
	rows   uint64
	closed bool
	gz     sync.WaitGroup
	err    error
}

// NewWriter creates dir if needed. Files are named
// <base>-YYYYMMDDTHHZ.csv, gzipped to .csv.gz when the hour ends.
func NewWriter(dir, base string, header []string) (*Writer, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &Writer{dir: dir, base: base, header: header, now: time.Now}, nil
}

// Write appends one row. Rows with the wrong column count are an
// error: the schema is fixed.
func (w *Writer) Write(row []string) error {
	if len(row) != len(w.header) {
		return fmt.Errorf("%s: row has %d columns, header %d", w.base, len(row), len(w.header))
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return fmt.Errorf("%s: writer closed", w.base)
	}
	hour := w.now().UTC().Truncate(time.Hour)
	if w.f == nil || !hour.Equal(w.hour) {
		if err := w.rotate(hour); err != nil {
			w.err = err
			return err
		}
	}
	w.rows++
	return w.cw.Write(row)
}

func (w *Writer) rotate(hour time.Time) error {
	if w.f != nil {
		w.closeFile(true)
	}
	name := filepath.Join(w.dir, fmt.Sprintf("%s-%s.csv", w.base, hour.Format("20060102T15Z")))
	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	st, _ := f.Stat()
	w.f, w.hour = f, hour
	w.bw = bufio.NewWriterSize(f, 256<<10)
	w.cw = csv.NewWriter(w.bw)
	if st == nil || st.Size() == 0 {
		return w.cw.Write(w.header)
	}
	return nil
}

// closeFile flushes and closes the current file; with compress, it is
// gzipped in the background and the plain file removed.
func (w *Writer) closeFile(compress bool) {
	w.cw.Flush()
	_ = w.bw.Flush()
	name := w.f.Name()
	_ = w.f.Close()
	w.f = nil
	if compress {
		w.gz.Add(1)
		go func() {
			defer w.gz.Done()
			_ = gzipFile(name)
		}()
	}
}

// Flush pushes buffered rows to disk.
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return w.err
	}
	w.cw.Flush()
	if err := w.bw.Flush(); err != nil {
		return err
	}
	return w.cw.Error()
}

// Rows is the number of rows written.
func (w *Writer) Rows() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.rows
}

// Close flushes, gzips the last file and waits for compression.
func (w *Writer) Close() error {
	w.mu.Lock()
	if !w.closed {
		w.closed = true
		if w.f != nil {
			w.closeFile(true)
		}
	}
	w.mu.Unlock()
	w.gz.Wait()
	return w.err
}

func gzipFile(name string) error {
	in, err := os.Open(name)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := name + ".gz.tmp"
	outf, err := os.Create(tmp)
	if err != nil {
		return err
	}
	zw := gzip.NewWriter(outf)
	if _, err := io.Copy(zw, in); err != nil {
		outf.Close()
		return err
	}
	if err := zw.Close(); err != nil {
		outf.Close()
		return err
	}
	if err := outf.Close(); err != nil {
		return err
	}
	in.Close()
	if err := os.Rename(tmp, name+".gz"); err != nil {
		return err
	}
	return os.Remove(name)
}

// Set is the run's group of writers, flushed together every second.
type Set struct {
	ws   map[string]*Writer
	stop chan struct{}
	done chan struct{}
}

// NewSet opens one writer per schema in dir.
func NewSet(dir string, schemas map[string][]string) (*Set, error) {
	s := &Set{ws: map[string]*Writer{}, stop: make(chan struct{}), done: make(chan struct{})}
	for name, header := range schemas {
		w, err := NewWriter(dir, name, header)
		if err != nil {
			return nil, err
		}
		s.ws[name] = w
	}
	go func() {
		defer close(s.done)
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				for _, w := range s.ws {
					_ = w.Flush()
				}
			case <-s.stop:
				return
			}
		}
	}()
	return s, nil
}

// W returns the named writer.
func (s *Set) W(name string) *Writer { return s.ws[name] }

// Close stops the flusher and closes every writer.
func (s *Set) Close() error {
	close(s.stop)
	<-s.done
	var first error
	for _, w := range s.ws {
		if err := w.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
