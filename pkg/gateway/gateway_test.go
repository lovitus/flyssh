package gateway

import "testing"

func TestParseGatewaySpec(t *testing.T) {
	user, password, bindAddr, err := parseGatewaySpec("admin:secret@127.0.0.1:2222")
	if err != nil {
		t.Fatalf("parseGatewaySpec returned error: %v", err)
	}
	if user != "admin" || password != "secret" || bindAddr != "127.0.0.1:2222" {
		t.Fatalf("unexpected parse result: user=%q password=%q bind=%q", user, password, bindAddr)
	}
}

func TestParseGatewaySpecRequiresPort(t *testing.T) {
	_, _, _, err := parseGatewaySpec("admin:secret@127.0.0.1")
	if err == nil {
		t.Fatal("expected missing port to fail")
	}
}

func TestParseGatewaySpecDoesNotUnescapePassword(t *testing.T) {
	_, password, _, err := parseGatewaySpec(`admin:p\@ss@127.0.0.1:2222`)
	if err != nil {
		t.Fatalf("parseGatewaySpec returned error: %v", err)
	}
	if password != `p\@ss` {
		t.Fatalf("password = %q, want current simple-parser behavior", password)
	}
}
