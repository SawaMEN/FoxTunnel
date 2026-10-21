package authheader

import (
	"net/http"
	"testing"
)

func TestAuditUTF8UsernameAcceptedByWireParser(t *testing.T) {
	name, secret, ok := Parse(http.Header{"Proxy-Authorization": {basic("пользователь", "secret")}})
	if !ok || name != "пользователь" || secret != "secret" {
		t.Fatal("valid UTF-8 profile credentials cannot authenticate")
	}
}
