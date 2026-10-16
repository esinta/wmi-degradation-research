package wmi

import (
	"fmt"
	"time"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"

	"wmiresearch/probe/internal/ledger"
)

// Pre-flight helpers. They run on the connection's thread like queries.

// ClassProvider returns the class's "provider" qualifier, or "" when the
// class has none (served from the repository).
func (c *Conn) ClassProvider(class string) (provider string, ei *ErrInfo) {
	err := c.run(func(l *ledger.Ledger, svc *ole.IDispatch) {
		defer func() {
			if r := recover(); r != nil {
				ei = &ErrInfo{Op: "ClassProvider", Text: fmt.Sprint("panic: ", r)}
			}
		}()
		cls, err := callMethod(l, svc, "Get", class)
		if err != nil {
			ei = errInfo("Get", err)
			return
		}
		defer cls.clear()
		cd, err := cls.dispatch()
		if err != nil {
			ei = &ErrInfo{Op: "Get", Text: err.Error()}
			return
		}
		qs, err := getProp(l, cd, "Qualifiers_")
		if err != nil {
			ei = errInfo("Qualifiers_", err)
			return
		}
		defer qs.clear()
		qd, err := qs.dispatch()
		if err != nil {
			ei = &ErrInfo{Op: "Qualifiers_", Text: err.Error()}
			return
		}
		q, err := callMethod(l, qd, "Item", "provider")
		if err != nil {
			return // no provider qualifier: repository class
		}
		defer q.clear()
		qi, err := q.dispatch()
		if err != nil {
			return
		}
		v, err := getProp(l, qi, "Value")
		if err != nil {
			ei = errInfo("Value", err)
			return
		}
		if v.v.VT == ole.VT_BSTR {
			provider = v.v.ToString()
		}
		v.clear()
	})
	if err != nil && ei == nil {
		ei = &ErrInfo{Op: "ClassProvider", Text: err.Error()}
	}
	return
}

// ForEachComparison is the H-enum check (design §2.2, §8): the same query
// enumerated the way go-ole's oleutil.ForEach does it, which is what Esinta
// and the old probe use.
type ForEachComparison struct {
	ExecErr    *ErrInfo
	ForEachErr *ErrInfo // nil means ForEach reported success
	Items      int
	Elapsed    time.Duration
}

// QueryForEach runs wql with Esinta's flags and enumerates it with
// oleutil.ForEach, counting items. Items are cleared.
func (c *Conn) QueryForEach(wql string) (out ForEachComparison) {
	t0 := time.Now()
	err := c.run(func(l *ledger.Ledger, svc *ole.IDispatch) {
		rs, err := callMethod(l, svc, "ExecQuery", wql, "WQL", wbemFlagReturnImmediately|wbemFlagForwardOnly)
		if err != nil {
			out.ExecErr = errInfo("ExecQuery", err)
			return
		}
		defer rs.clear()
		set, err := rs.dispatch()
		if err != nil {
			out.ExecErr = &ErrInfo{Op: "ExecQuery", Text: err.Error()}
			return
		}
		ferr := oleutil.ForEach(set, func(v *ole.VARIANT) error {
			out.Items++
			own(l, v, "item").clear()
			return nil
		})
		if ferr != nil {
			out.ForEachErr = errInfo("ForEach", ferr)
		}
	})
	if err != nil {
		out.ExecErr = &ErrInfo{Op: "QueryForEach", Text: err.Error()}
	}
	out.Elapsed = time.Since(t0)
	return
}
