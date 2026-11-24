package branding

import "testing"

func TestIdentityAndCommandPattern(t *testing.T) {
	if ProductName != "Wapo Review" || ServiceName != "wapo-review" || PrimaryCommand != "/wapo-review" {
		t.Fatal("unexpected product identity")
	}
	pattern := CommandPatternFor("other-bot")
	if !pattern.MatchString("please /other-bot review") || pattern.MatchString("/wapo-review") {
		t.Fatal("command pattern should use the supplied slug")
	}
}
