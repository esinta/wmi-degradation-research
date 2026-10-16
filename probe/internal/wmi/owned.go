package wmi

import (
	"errors"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"

	"wmiresearch/probe/internal/hresult"
	"wmiresearch/probe/internal/ledger"
)

// owned is a VARIANT the client is responsible for. It is cleared exactly
// once through clear(); a second clear is counted as a double release in the
// ledger and does not call VariantClear again.
type owned struct {
	v    *ole.VARIANT
	tok  uint64
	l    *ledger.Ledger
	done bool
}

func own(l *ledger.Ledger, v *ole.VARIANT, kind string) *owned {
	if v == nil {
		return nil
	}
	return &owned{v: v, tok: l.Acquire(kind), l: l}
}

// clear frees the VARIANT once. By-reference VARIANTs do not own what they
// point to and are only checked off.
func (o *owned) clear() {
	if o == nil {
		return
	}
	if o.done {
		o.l.Release(o.tok) // counts the double release
		return
	}
	o.done = true
	if o.l.Release(o.tok) && o.v.VT&ole.VT_BYREF == 0 && o.v.VT != ole.VT_EMPTY && o.v.VT != ole.VT_NULL {
		_ = o.v.Clear()
	}
}

// leak leaves the VARIANT unfreed on purpose (buggy arms only).
func (o *owned) leak() {
	if o == nil || o.done {
		return
	}
	o.done = true
	o.l.Leak(o.tok)
}

// dispatch returns the IDispatch the VARIANT holds (a cast: no AddRef; the
// reference stays owned by the VARIANT).
func (o *owned) dispatch() (*ole.IDispatch, error) {
	if o == nil || o.v == nil {
		return nil, errors.New("nil variant")
	}
	if o.v.VT != ole.VT_DISPATCH {
		return nil, errors.New("variant is not VT_DISPATCH")
	}
	d := o.v.ToIDispatch()
	if d == nil {
		return nil, errors.New("null IDispatch")
	}
	return d, nil
}

// getProp reads a property and registers the result.
func getProp(l *ledger.Ledger, d *ole.IDispatch, name string) (*owned, error) {
	v, err := oleutil.GetProperty(d, name)
	if err != nil {
		return nil, err
	}
	return own(l, v, "prop:"+name), nil
}

// callMethod calls a method and registers the result.
func callMethod(l *ledger.Ledger, d *ole.IDispatch, name string, args ...any) (*owned, error) {
	v, err := oleutil.CallMethod(d, name, args...)
	if err != nil {
		return nil, err
	}
	return own(l, v, "call:"+name), nil
}

// errInfo captures an error from go-ole completely: the outer HRESULT and,
// for an IDispatch exception, the EXCEPINFO scode, wCode, source and text.
func errInfo(op string, err error) *ErrInfo {
	if err == nil {
		return nil
	}
	ei := &ErrInfo{Op: op, Text: truncate(err.Error(), 200)}
	var oe *ole.OleError
	if errors.As(err, &oe) {
		ei.HR = uint32(oe.Code())
		if ex, ok := oe.SubError().(ole.EXCEPINFO); ok {
			ei.SCode = ex.SCODE()
			ei.WCode = ex.WCode()
			ei.Src = truncate(ex.String(), 200)
		}
	}
	return ei
}

func hrErr(op string, hr uint32, text string) *ErrInfo {
	return &ErrInfo{Op: op, HR: hr, Text: text + " (" + hresult.Name(hr) + ")"}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
