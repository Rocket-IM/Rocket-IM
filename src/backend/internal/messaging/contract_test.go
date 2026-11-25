package messaging

import "testing"

func TestStrictRequestObjectsAndLosslessCursors(t *testing.T) {
	for _, raw := range []string{`null`, `[]`, `{"sequence":"1","unexpected":true}`, `{"sequence":1}`, `{"sequence":"1"} {}`} {
		var input Processed
		if Decode([]byte(raw), &input) == nil {
			t.Fatalf("invalid object accepted: %s", raw)
		}
	}
	var valid Processed
	if e := Decode([]byte(`{"sequence":"9007199254740993"}`), &valid); e != nil {
		t.Fatal(e)
	}
	n, e := Number(valid.Sequence)
	if e != nil || n != 9007199254740993 {
		t.Fatal("lossy cursor")
	}
	for _, value := range []string{"-1", "00", "1.0", "1e3", "9223372036854775808"} {
		if _, e := Number(value); e == nil {
			t.Fatal("noncanonical cursor")
		}
	}
}
