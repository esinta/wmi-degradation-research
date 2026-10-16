// Package hresult names the HRESULTs the probe meets and classifies them for
// the refresh strategies. The raw codes are always recorded; names are only
// for reading.
//
// Note: Esinta's errors.go table is shifted by one from 0x8004100D on (it
// has no WBEM_E_INVALID_SUPERCLASS), so its WBEM_E_INVALID_NAMESPACE is
// 0x8004100D instead of 0x8004100E. The values here follow wbemcli.h.
package hresult

import "fmt"

const (
	SOK    uint32 = 0x00000000
	SFalse uint32 = 0x00000001

	DispEException     uint32 = 0x80020009 // IDispatch::Invoke raised; the real code is in EXCEPINFO.scode
	RPCEDisconnected   uint32 = 0x80010108
	RPCEServerFault    uint32 = 0x80010105
	RPCECallRejected   uint32 = 0x80010001
	RPCSServerUnavail  uint32 = 0x800706BA
	RPCSCallFailed     uint32 = 0x800706BE
	RPCSCallFailedDNE  uint32 = 0x800706BF
	COENotInitialized  uint32 = 0x800401F0
	COEObjNotConnected uint32 = 0x800401FD
	EAccessDenied      uint32 = 0x80070005
	EOutOfMemory       uint32 = 0x8007000E

	WBEMEFailed           uint32 = 0x80041001
	WBEMENotFound         uint32 = 0x80041002
	WBEMEAccessDenied     uint32 = 0x80041003
	WBEMEProviderFailure  uint32 = 0x80041004
	WBEMETypeMismatch     uint32 = 0x80041005
	WBEMEOutOfMemory      uint32 = 0x80041006
	WBEMEInvalidContext   uint32 = 0x80041007
	WBEMEInvalidParameter uint32 = 0x80041008
	WBEMENotAvailable     uint32 = 0x80041009
	WBEMECriticalError    uint32 = 0x8004100A
	WBEMENotSupported     uint32 = 0x8004100C
	WBEMEInvalidNamespace uint32 = 0x8004100E
	WBEMEInvalidObject    uint32 = 0x8004100F
	WBEMEInvalidClass     uint32 = 0x80041010
	WBEMEProviderNotFound uint32 = 0x80041011
	WBEMEProviderLoadFail uint32 = 0x80041013
	WBEMETransportFailure uint32 = 0x80041015
	WBEMEInvalidQuery     uint32 = 0x80041017
	WBEMEShuttingDown     uint32 = 0x80041033
	WBEMETimedOut         uint32 = 0x80043001
	WBEMEUnparsableQuery  uint32 = 0x80041058
	WBEMEQuotaViolation   uint32 = 0x8004106C
	WBEMEServerTooBusy    uint32 = 0x80041045
)

var names = map[uint32]string{
	SOK: "S_OK", SFalse: "S_FALSE",
	DispEException: "DISP_E_EXCEPTION", RPCEDisconnected: "RPC_E_DISCONNECTED", RPCEServerFault: "RPC_E_SERVERFAULT",
	RPCECallRejected: "RPC_E_CALL_REJECTED", RPCSServerUnavail: "RPC_S_SERVER_UNAVAILABLE", RPCSCallFailed: "RPC_S_CALL_FAILED",
	RPCSCallFailedDNE: "RPC_S_CALL_FAILED_DNE", COENotInitialized: "CO_E_NOTINITIALIZED", COEObjNotConnected: "CO_E_OBJNOTCONNECTED",
	EAccessDenied: "E_ACCESSDENIED", EOutOfMemory: "E_OUTOFMEMORY",
	WBEMEFailed: "WBEM_E_FAILED", WBEMENotFound: "WBEM_E_NOT_FOUND", WBEMEAccessDenied: "WBEM_E_ACCESS_DENIED",
	WBEMEProviderFailure: "WBEM_E_PROVIDER_FAILURE", WBEMETypeMismatch: "WBEM_E_TYPE_MISMATCH", WBEMEOutOfMemory: "WBEM_E_OUT_OF_MEMORY",
	WBEMEInvalidContext: "WBEM_E_INVALID_CONTEXT", WBEMEInvalidParameter: "WBEM_E_INVALID_PARAMETER", WBEMENotAvailable: "WBEM_E_NOT_AVAILABLE",
	WBEMECriticalError: "WBEM_E_CRITICAL_ERROR", WBEMENotSupported: "WBEM_E_NOT_SUPPORTED", WBEMEInvalidNamespace: "WBEM_E_INVALID_NAMESPACE",
	WBEMEInvalidObject: "WBEM_E_INVALID_OBJECT", WBEMEInvalidClass: "WBEM_E_INVALID_CLASS", WBEMEProviderNotFound: "WBEM_E_PROVIDER_NOT_FOUND",
	WBEMEProviderLoadFail: "WBEM_E_PROVIDER_LOAD_FAILURE", WBEMETransportFailure: "WBEM_E_TRANSPORT_FAILURE", WBEMEInvalidQuery: "WBEM_E_INVALID_QUERY",
	WBEMEShuttingDown: "WBEM_E_SHUTTING_DOWN", WBEMETimedOut: "WBEM_E_TIMED_OUT", WBEMEUnparsableQuery: "WBEM_E_UNPARSABLE_QUERY",
	WBEMEQuotaViolation: "WBEM_E_QUOTA_VIOLATION", WBEMEServerTooBusy: "WBEM_E_SERVER_TOO_BUSY",
}

// Name returns the symbolic name, or the hex code when unknown.
func Name(hr uint32) string {
	if n, ok := names[hr]; ok {
		return n
	}
	return Hex(hr)
}

// Hex formats a code as 0xXXXXXXXX.
func Hex(hr uint32) string { return fmt.Sprintf("0x%08X", hr) }

// Effective is the code that describes the failure: the EXCEPINFO scode when
// the outer HRESULT is DISP_E_EXCEPTION and an scode is present, else the
// outer HRESULT.
func Effective(outer, scode uint32) uint32 {
	if outer == DispEException && scode != 0 {
		return scode
	}
	return outer
}

// ConnectionLevel reports whether a code means the connection itself is
// broken: the adaptive strategy's error trigger (pre-registered list,
// design §4.1 arm E2). It is checked against the effective code.
func ConnectionLevel(code uint32) bool {
	switch code {
	case RPCEDisconnected, RPCEServerFault, RPCSServerUnavail, RPCSCallFailed, RPCSCallFailedDNE,
		COEObjNotConnected, COENotInitialized, WBEMETransportFailure, WBEMEShuttingDown, WBEMENotAvailable,
		WBEMECriticalError:
		return true
	}
	return false
}

// EsintaUnhealthy reproduces Esinta's shouldMarkUnhealthy(mapWindowsError(
// OleError.Code())) for the pool-equivalent arm E3. Esinta maps the *outer*
// HRESULT, so an error wrapped as DISP_E_EXCEPTION never matches; the arm
// copies that behaviour on purpose.
func EsintaUnhealthy(outer uint32) bool {
	switch outer {
	case WBEMEAccessDenied, WBEMETransportFailure, WBEMENotAvailable, COENotInitialized:
		return true
	}
	return false
}
