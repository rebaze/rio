package gate

import "testing"

func TestValidSpecVersion(t *testing.T) {
	for v, want := range map[string]bool{
		"1.6": true, "1.7": true, "2.0": true, "1.6.1": true, "10.0": true,
		"1.5": false, "1.x": false, "banana": false, "1..6": false, "": false, "1.6.": false, "+1.6": false, "1.-6": false,
	} {
		if got := validSpecVersion(v); got != want {
			t.Errorf("validSpecVersion(%q) = %v, want %v", v, got, want)
		}
	}
}
