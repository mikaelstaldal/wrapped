package wrapped

import (
	"os"
	"path/filepath"
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

func TestValidatePortRanges(t *testing.T) {
	valid := []string{"80", "443", "1024-65535", "0", "8080-8090"}
	if err := validatePortRanges("--expose-tcp", valid); err != nil {
		t.Errorf("unexpected error for valid ports: %v", err)
	}

	invalid := []string{"abc", "80-", "-443", "80:443", "80/tcp"}
	for _, p := range invalid {
		if err := validatePortRanges("--expose-tcp", []string{p}); err == nil {
			t.Errorf("expected error for port %q, got nil", p)
		}
	}
}

func TestIsParentOrEqual(t *testing.T) {
	cases := []struct {
		parent, child string
		want          bool
	}{
		{"/home/user", "/home/user", true},
		{"/home/user", "/home/user/project", true},
		{"/home/user", "/home/user2", false},
		{"/home", "/home/user", true},
		{"/usr", "/usr/bin/go", true},
		{"/usr/bin", "/usr", false},
	}
	for _, c := range cases {
		got := isParentOrEqual(c.parent, c.child)
		if got != c.want {
			t.Errorf("isParentOrEqual(%q, %q) = %v, want %v", c.parent, c.child, got, c.want)
		}
	}
}

func TestIsCovered(t *testing.T) {
	dirs := []string{"/usr", "/home/user/project"}
	cases := []struct {
		file string
		want bool
	}{
		{"/usr/bin/go", true},
		{"/usr", true},
		{"/home/user/project/main.go", true},
		{"/home/user", false},
		{"/etc/passwd", false},
	}
	for _, c := range cases {
		got := isCovered(c.file, dirs)
		if got != c.want {
			t.Errorf("isCovered(%q) = %v, want %v", c.file, got, c.want)
		}
	}
}

func TestIsForbiddenMountTarget(t *testing.T) {
	forbidden := []string{"/", "/proc", "/dev", "/sys"}
	for _, p := range forbidden {
		if !isForbiddenMountTarget(p) {
			t.Errorf("expected %q to be forbidden", p)
		}
	}

	allowed := []string{"/home/user", "/tmp/mydir", "/opt/data"}
	for _, p := range allowed {
		if isForbiddenMountTarget(p) {
			t.Errorf("expected %q to be allowed", p)
		}
	}
}

func TestValidateSymlinkSrc(t *testing.T) {
	sandbox := []string{"/usr", "/tmp", "/home/user/project"}

	// Relative paths always OK.
	if err := validateSymlinkSrc("../lib", sandbox); err != nil {
		t.Errorf("unexpected error for relative path: %v", err)
	}

	// Absolute paths inside sandbox OK.
	if err := validateSymlinkSrc("/usr/lib", sandbox); err != nil {
		t.Errorf("unexpected error for /usr/lib: %v", err)
	}
	if err := validateSymlinkSrc("/home/user/project/file", sandbox); err != nil {
		t.Errorf("unexpected error for project path: %v", err)
	}

	// Absolute paths outside sandbox rejected.
	if err := validateSymlinkSrc("/etc/passwd", sandbox); err == nil {
		t.Error("expected error for /etc/passwd outside sandbox")
	}
	if err := validateSymlinkSrc("/root/secret", sandbox); err == nil {
		t.Error("expected error for /root/secret outside sandbox")
	}
}

func TestShellQuote(t *testing.T) {
	cases := []struct{ in, want string }{
		{"hello", "'hello'"},
		{"hello world", "'hello world'"},
		{"it's", "'it'\\''s'"},
		{"", "''"},
		{"/usr/bin/bwrap", "'/usr/bin/bwrap'"},
		{"foo'bar'baz", "'foo'\\''bar'\\''baz'"},
	}
	for _, c := range cases {
		got := shellQuote(c.in)
		if got != c.want {
			t.Errorf("shellQuote(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseResolvConf(t *testing.T) {
	content := "# comment\nnameserver 1.1.1.1\nnameserver 8.8.8.8\nsearch example.com\nnameserver not-an-ip\n"
	f, err := os.CreateTemp(t.TempDir(), "resolv.conf")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()

	ips, err := parseResolvConf(f.Name())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 2 || ips[0] != "1.1.1.1" || ips[1] != "8.8.8.8" {
		t.Errorf("got IPs %v, want [1.1.1.1 8.8.8.8]", ips)
	}

	_, err = parseResolvConf(filepath.Join(t.TempDir(), "nonexistent"))
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestBuildNftRules(t *testing.T) {
	rules := buildNftRules([]string{"1.2.3.4", "2001:db8::1"}, []string{"8.8.8.8", "2001:4860:4860::8888"})

	mustContain := []string{
		"table inet filter",
		"chain output",
		"policy drop",
		"ct state established,related accept",
		"oifname lo accept",
		"ip daddr { 1.2.3.4 } accept",
		"ip6 daddr { 2001:db8::1 } accept",
		"ip daddr { 8.8.8.8 } meta l4proto { tcp, udp } th dport 53 accept",
		"ip6 daddr { 2001:4860:4860::8888 } meta l4proto { tcp, udp } th dport 53 accept",
	}
	for _, s := range mustContain {
		if !strings.Contains(rules, s) {
			t.Errorf("nft rules missing %q\nfull rules:\n%s", s, rules)
		}
	}
}

func TestBuildNftRulesEmpty(t *testing.T) {
	rules := buildNftRules(nil, nil)
	if !strings.Contains(rules, "policy drop") {
		t.Error("rules should still have drop policy when no IPs given")
	}
	if strings.Contains(rules, "ip daddr") {
		t.Error("rules should have no ip daddr rules when no IPs given")
	}
}

func TestWrappedExposeTCPUDPRequiresBridge(t *testing.T) {
	cases := []struct {
		network string
		tcp     []string
		udp     []string
	}{
		{NetworkNone, []string{"80"}, nil},
		{NetworkNone, nil, []string{"53"}},
		{NetworkHost, []string{"443"}, nil},
		{NetworkFiltered, []string{"8080"}, nil},
		{NetworkFiltered, nil, []string{"123"}},
	}
	for _, c := range cases {
		err := Wrapped("true", nil, c.network, false, false, nil, nil, nil, nil, "", "", nil, false, false, nil, c.tcp, c.udp)
		if err == nil {
			t.Errorf("expected error for network=%q tcp=%v udp=%v", c.network, c.tcp, c.udp)
			continue
		}
		if !strings.Contains(err.Error(), "--expose-tcp and --expose-udp can only be used with --network bridge") {
			t.Errorf("unexpected error for network=%q: %v", c.network, err)
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
