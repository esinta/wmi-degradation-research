package wmi

import (
	"errors"
	"unsafe"

	"github.com/go-ole/go-ole"

	"wmiresearch/probe/internal/clock"
	"wmiresearch/probe/internal/hresult"
	"wmiresearch/probe/internal/ledger"
)

// enumerate walks d's _NewEnum strictly (design §2.2). fn receives each item
// as an owned VARIANT, which enumerate clears after fn returns.
//
// go-ole's oleutil.ForEach loops `for item, length, err := enum.Next(1);
// length > 0; ...`, so a Next that fails with zero items ends the loop and
// ForEach returns nil: a failed enumeration looks like a normal end. Here
// only S_FALSE (or S_OK with zero items) is a normal end; anything else is
// returned as an error with the rows delivered before it.
//
// endHR is the HRESULT that ended the walk; first is the time the first
// Next returned (zero if none ran).
func enumerate(l *ledger.Ledger, d *ole.IDispatch, op string, fn func(item *owned)) (endHR uint32, n int, first clock.Mark, ei *ErrInfo) {
	ev, err := getProp(l, d, "_NewEnum")
	if err != nil {
		ei = errInfo(op+"._NewEnum", err)
		return ei.HR, 0, first, ei
	}
	defer ev.clear()

	var unk *ole.IUnknown
	switch ev.v.VT {
	case ole.VT_UNKNOWN:
		unk = ev.v.ToIUnknown()
	case ole.VT_DISPATCH:
		unk = (*ole.IUnknown)(unsafe.Pointer(ev.v.ToIDispatch()))
	}
	if unk == nil {
		return 0, 0, first, &ErrInfo{Op: op + "._NewEnum", Text: "enumerator is not an interface"}
	}
	enum, err := unk.IEnumVARIANT(ole.IID_IEnumVariant)
	if err != nil {
		ei = errInfo(op+".QueryInterface(IEnumVARIANT)", err)
		return ei.HR, 0, first, ei
	}
	tok := l.Acquire("enum")
	defer func() {
		if l.Release(tok) {
			enum.Release()
		}
	}()

	for {
		item, fetched, err := enum.Next(1)
		if first.IsZero() {
			first = clock.Now()
		}
		hr := hresult.SOK
		if err != nil {
			var oe *ole.OleError
			if errors.As(err, &oe) {
				hr = uint32(oe.Code())
			} else {
				hr = hresult.WBEMEFailed
			}
		}
		if fetched > 0 {
			it := item
			o := own(l, &it, "item")
			fn(o)
			o.clear()
			n++
		}
		switch {
		case hr == hresult.SOK && fetched > 0:
			continue
		case hr == hresult.SOK, hr == hresult.SFalse:
			return hr, n, first, nil
		default:
			return hr, n, first, hrErr(op+".Next", hr, "enumeration ended with an error after "+itoa(n)+" items")
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// convert turns a property value into a Go value. It reports whether the
// value was a SAFEARRAY and how many elements it had. The VARIANT is not
// cleared here; the caller owns it.
func convert(v *ole.VARIANT) (val any, isArray bool, elems int) {
	if v.VT&ole.VT_ARRAY != 0 {
		sa := v.ToArray()
		if sa == nil || sa.Array == nil {
			return nil, true, 0
		}
		vals := sa.ToValueArray() // copies; BSTR elements freed, VARIANT elements cleared
		return vals, true, len(vals)
	}
	switch v.VT {
	case ole.VT_EMPTY, ole.VT_NULL:
		return nil, false, 0
	case ole.VT_BSTR:
		return v.ToString(), false, 0
	case ole.VT_DISPATCH, ole.VT_UNKNOWN:
		return "<object>", false, 0 // embedded object; clearing the VARIANT releases it
	default:
		return v.Value(), false, 0
	}
}
