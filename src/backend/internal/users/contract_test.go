package users

import "testing"

func TestBusinessOperationShapesAreUnambiguous(t *testing.T) {
	valid := `{"service":"service","request_id":"r","external_user":"u"}`
	if _, e := Decode("users", []byte(valid)); e != nil {
		t.Fatal(e)
	}
	for _, raw := range []string{
		`{"service":"service","service":"other","request_id":"r","external_user":"u"}`,
		`{"service":"service","request_id":"r","external_user":"u","ttl_seconds":0}`,
		`{"service":"service","request_id":"r","external_user":"u","identity_key":null}`,
		`{"service":"service","request_id":"r"}`,
		`{"service":"service","request_id":"r","external_user":null}`,
	} {
		if _, e := Decode("users", []byte(raw)); e == nil {
			t.Fatal("ambiguous shape accepted")
		}
	}
}
