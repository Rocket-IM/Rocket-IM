package auth

import (
	"strings"
	"testing"
)

func TestTokenBindsPurposeServiceAndID(t *testing.T) {
	key := strings.Repeat("ab", 32)
	id := strings.Repeat("01", 16)
	token := Token(key, "one", id)
	if got, ok := Verify(key, "one", token); !ok || got != id {
		t.Fatal("valid token failed")
	}
	for _, bad := range []string{strings.Replace(token, "rimd_", "rimb_", 1), token + "x", token[:len(token)-1] + "z", Token(key, "two", id), Token(strings.Repeat("cd", 32), "one", id)} {
		if _, ok := Verify(key, "one", bad); ok {
			t.Fatal("invalid token accepted")
		}
	}
}
