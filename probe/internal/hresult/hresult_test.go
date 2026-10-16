package hresult

import "testing"

func TestEffective(t *testing.T) {
	if got := Effective(DispEException, WBEMEInvalidClass); got != WBEMEInvalidClass {
		t.Errorf("got %s", Hex(got))
	}
	if got := Effective(DispEException, 0); got != DispEException {
		t.Errorf("got %s", Hex(got))
	}
	if got := Effective(RPCSServerUnavail, WBEMEFailed); got != RPCSServerUnavail {
		t.Errorf("got %s", Hex(got))
	}
}

func TestWbemValuesFollowWbemcli(t *testing.T) {
	// The values Esinta's table gets wrong.
	if WBEMEInvalidNamespace != 0x8004100E || WBEMEInvalidClass != 0x80041010 || WBEMEProviderNotFound != 0x80041011 {
		t.Fatal("WBEM constants drifted")
	}
	if Name(WBEMEInvalidNamespace) != "WBEM_E_INVALID_NAMESPACE" || Name(0x12345678) != "0x12345678" {
		t.Fatal("Name")
	}
}

func TestClasses(t *testing.T) {
	if !ConnectionLevel(RPCSServerUnavail) || ConnectionLevel(WBEMEInvalidClass) {
		t.Error("ConnectionLevel")
	}
	// Esinta maps the outer code: a wrapped transport failure is not unhealthy.
	if EsintaUnhealthy(DispEException) || !EsintaUnhealthy(WBEMETransportFailure) {
		t.Error("EsintaUnhealthy")
	}
}
