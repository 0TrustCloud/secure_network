package secure_network

import "testing"

func TestDBSCIncludeSiteAllowed(t *testing.T) {
	cases := map[string]bool{
		"defcon.chat":          true,
		"bandy.chat":           true,
		"0trust.cloud":         true,
		"defcon.0trust.cloud":  false,
		"bandy.0trust.cloud":   false,
		"social.0trust.cloud":  false,
		"williwaw.app":         true,
		"www.williwaw.app":     false,
		"127.0.0.1":            false,
		"":                     false,
	}
	for host, want := range cases {
		if got := dbscIncludeSiteAllowed(host); got != want {
			t.Fatalf("host %q: got %v want %v", host, got, want)
		}
	}
}
