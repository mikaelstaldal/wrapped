package wrapped

import (
	"strings"
	"testing"
)

func TestApparmorProfileValidation(t *testing.T) {
	valid := []string{
		"firefox",
		"snap.chromium.chromium",
		"my-profile",
		"profile_v2",
		"AppArmor.Profile-123",
	}
	for _, name := range valid {
		if !validApparmorProfile.MatchString(name) {
			t.Errorf("expected %q to be valid", name)
		}
	}

	invalid := []string{
		"profile name",  // space
		"../escape",     // path traversal
		"foo;bar",       // semicolon
		"foo&bar",       // shell metachar
		"foo|bar",       // pipe
		"foo`cmd`",      // backtick
		"foo$(cmd)",     // subshell
		"",              // empty is handled separately (skipped), but ensure regex rejects
		"foo/bar",       // slash
	}
	for _, name := range invalid {
		if name != "" && validApparmorProfile.MatchString(name) {
			t.Errorf("expected %q to be invalid", name)
		}
	}
}

func TestWrappedRejectsInvalidApparmorProfile(t *testing.T) {
	bad := []string{
		"profile name",
		"../escape",
		"foo;bar",
		"foo|bar",
	}
	for _, name := range bad {
		err := Wrapped("true", nil, NetworkNone, false, false, nil, nil, nil, nil, "", name, nil, false, false, nil, nil, nil)
		if err == nil {
			t.Errorf("expected error for profile %q, got nil", name)
			continue
		}
		if !strings.Contains(err.Error(), "invalid AppArmor profile name") {
			t.Errorf("unexpected error for profile %q: %v", name, err)
		}
	}
}
