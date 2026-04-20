package wrapped

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// containsSeq reports whether args contains the given consecutive subsequence.
func containsSeq(args []string, seq ...string) bool {
	for i := 0; i <= len(args)-len(seq); i++ {
		match := true
		for j, s := range seq {
			if args[i+j] != s {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// containsArg reports whether args contains the given single element.
func containsArg(args []string, arg string) bool {
	return slices.Contains(args, arg)
}

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
		"profile name", // space
		"../escape",    // path traversal
		"foo;bar",      // semicolon
		"foo&bar",      // shell metachar
		"foo|bar",      // pipe
		"foo`cmd`",     // backtick
		"foo$(cmd)",    // subshell
		"",             // empty is handled separately (skipped), but ensure regex rejects
		"foo/bar",      // slash
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

// testProgram returns an absolute path to an existing executable suitable for
// use as the program argument in build*Args tests.
func testProgram(t *testing.T) string {
	t.Helper()
	return os.Args[0] // the test binary itself
}

func TestBuildBaseBwrapArgsStructure(t *testing.T) {
	prog := testProgram(t)
	args, err := buildBaseBwrapArgs(false, false, nil, nil, nil, nil, "", false, prog, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mustHaveSeq := [][]string{
		{"--ro-bind", "/usr", "/usr"},
		{"--symlink", "/usr/lib", "/lib"},
		{"--symlink", "/usr/lib64", "/lib64"},
		{"--symlink", "/usr/bin", "/bin"},
		{"--symlink", "/usr/sbin", "/sbin"},
		{"--tmpfs", "/tmp"},
		{"--proc", "/proc"},
		{"--dev", "/dev"},
	}
	for _, seq := range mustHaveSeq {
		if !containsSeq(args, seq...) {
			t.Errorf("args missing sequence %v\nfull args: %v", seq, args)
		}
	}

	for _, flag := range []string{"--unshare-user", "--unshare-ipc", "--unshare-pid", "--unshare-cgroup-try"} {
		if !containsArg(args, flag) {
			t.Errorf("args missing %q\nfull args: %v", flag, args)
		}
	}
}

func TestBuildBaseBwrapArgsClearEnv(t *testing.T) {
	prog := testProgram(t)

	// Without allEnv: --clearenv and default PATH should be present.
	args, err := buildBaseBwrapArgs(false, false, nil, nil, nil, nil, "", false, prog, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !containsArg(args, "--clearenv") {
		t.Errorf("expected --clearenv without allEnv\nfull args: %v", args)
	}
	if !containsSeq(args, "--setenv", "PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin") {
		t.Errorf("expected default PATH setenv\nfull args: %v", args)
	}

	// With allEnv: --clearenv must not appear, nor should default PATH be set.
	args, err = buildBaseBwrapArgs(false, false, nil, nil, nil, nil, "", true, prog, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if containsArg(args, "--clearenv") {
		t.Errorf("did not expect --clearenv with allEnv=true\nfull args: %v", args)
	}
	if containsSeq(args, "--setenv", "PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin") {
		t.Errorf("did not expect default PATH with allEnv=true\nfull args: %v", args)
	}
}

func TestBuildBaseBwrapArgsExtraEnv(t *testing.T) {
	prog := testProgram(t)

	// Extra env with KEY=VALUE form.
	args, err := buildBaseBwrapArgs(false, false, nil, nil, nil, []string{"FOO=bar", "BAZ=qux"}, "", false, prog, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !containsSeq(args, "--setenv", "FOO", "bar") {
		t.Errorf("expected --setenv FOO bar\nfull args: %v", args)
	}
	if !containsSeq(args, "--setenv", "BAZ", "qux") {
		t.Errorf("expected --setenv BAZ qux\nfull args: %v", args)
	}

	// Providing PATH in extraEnv suppresses the default PATH.
	args, err = buildBaseBwrapArgs(false, false, nil, nil, nil, []string{"PATH=/custom/bin"}, "", false, prog, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !containsSeq(args, "--setenv", "PATH", "/custom/bin") {
		t.Errorf("expected --setenv PATH /custom/bin\nfull args: %v", args)
	}
	if containsSeq(args, "--setenv", "PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin") {
		t.Errorf("did not expect default PATH when PATH already set\nfull args: %v", args)
	}
}

func TestBuildBaseBwrapArgsMountCurrentDir(t *testing.T) {
	prog := testProgram(t)
	cwd, _ := os.Getwd()
	cwd, _ = filepath.EvalSymlinks(cwd)

	// Read-only mount.
	args, err := buildBaseBwrapArgs(true, false, nil, nil, nil, nil, "", false, prog, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !containsSeq(args, "--ro-bind", cwd, cwd) {
		t.Errorf("expected --ro-bind for current dir\nfull args: %v", args)
	}
	if containsSeq(args, "--bind", cwd, cwd) {
		t.Errorf("did not expect --bind for read-only mount\nfull args: %v", args)
	}

	// Writable mount.
	args, err = buildBaseBwrapArgs(true, true, nil, nil, nil, nil, "", false, prog, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !containsSeq(args, "--bind", cwd, cwd) {
		t.Errorf("expected --bind for writable current dir\nfull args: %v", args)
	}
}

func TestBuildBaseBwrapArgsTmpfs(t *testing.T) {
	prog := testProgram(t)
	args, err := buildBaseBwrapArgs(false, false, nil, nil, nil, nil, "", false, prog, []string{"/run/cache"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !containsSeq(args, "--tmpfs", "/run/cache") {
		t.Errorf("expected --tmpfs /run/cache\nfull args: %v", args)
	}
}

func TestBuildBwrapArgsNoNetwork(t *testing.T) {
	prog := testProgram(t)
	args, err := buildBwrapArgs(prog, nil, false, false, false, nil, nil, nil, nil, "", "", false, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !containsArg(args, "--unshare-net") {
		t.Errorf("expected --unshare-net for no-network mode\nfull args: %v", args)
	}
	if !containsArg(args, "--unshare-uts") {
		t.Errorf("expected --unshare-uts for no-network mode\nfull args: %v", args)
	}
}

func TestBuildBwrapArgsHostNetwork(t *testing.T) {
	prog := testProgram(t)
	args, err := buildBwrapArgs(prog, nil, true, false, false, nil, nil, nil, nil, "", "", false, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if containsArg(args, "--unshare-net") {
		t.Errorf("did not expect --unshare-net for host network\nfull args: %v", args)
	}
	if containsArg(args, "--unshare-uts") {
		t.Errorf("did not expect --unshare-uts for host network\nfull args: %v", args)
	}
}

func TestBuildBwrapArgsAppArmor(t *testing.T) {
	prog := testProgram(t)
	resolvedProg, err := resolveProgram(prog)
	if err != nil {
		t.Fatalf("resolveProgram: %v", err)
	}

	args, err := buildBwrapArgs(prog, []string{"arg1"}, false, false, false, nil, nil, nil, nil, "", "my-profile", false, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// aa-exec -p profile -- must appear immediately before the program.
	if !containsSeq(args, "aa-exec", "-p", "my-profile", "--", resolvedProg, "arg1") {
		t.Errorf("expected aa-exec sequence before program\nfull args: %v", args)
	}
}

func TestBuildBwrapArgsProgramAndArguments(t *testing.T) {
	prog := testProgram(t)
	resolvedProg, err := resolveProgram(prog)
	if err != nil {
		t.Fatalf("resolveProgram: %v", err)
	}

	args, err := buildBwrapArgs(prog, []string{"--foo", "bar"}, false, false, false, nil, nil, nil, nil, "", "", false, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !containsSeq(args, resolvedProg, "--foo", "bar") {
		t.Errorf("expected program and arguments at end\nfull args: %v", args)
	}
}

func TestBuildPastaArgsNoPorts(t *testing.T) {
	args, err := buildPastaArgs("/usr/bin/bwrap", []string{"--unshare-user"}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !containsArg(args, "--config-net") {
		t.Errorf("expected --config-net\nfull args: %v", args)
	}
	// Host-to-namespace forwarding must be disabled.
	if !containsSeq(args, "-T", "none") {
		t.Errorf("expected -T none\nfull args: %v", args)
	}
	if !containsSeq(args, "-U", "none") {
		t.Errorf("expected -U none\nfull args: %v", args)
	}
	// No exposed ports → -t none and -u none.
	if !containsSeq(args, "-t", "none") {
		t.Errorf("expected -t none when no TCP ports exposed\nfull args: %v", args)
	}
	if !containsSeq(args, "-u", "none") {
		t.Errorf("expected -u none when no UDP ports exposed\nfull args: %v", args)
	}
	// Command separator and wrapped command must follow pasta flags.
	if !containsSeq(args, "--", "/usr/bin/bwrap", "--unshare-user") {
		t.Errorf("expected -- bwrap args at end\nfull args: %v", args)
	}
}

func TestBuildPastaArgsWithPorts(t *testing.T) {
	args, err := buildPastaArgs("/usr/bin/bwrap", nil, []string{"80", "443"}, []string{"53"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !containsSeq(args, "-t", "80,443") {
		t.Errorf("expected -t 80,443\nfull args: %v", args)
	}
	if !containsSeq(args, "-u", "53") {
		t.Errorf("expected -u 53\nfull args: %v", args)
	}
}

func TestBuildPastaArgsPortRange(t *testing.T) {
	args, err := buildPastaArgs("/usr/bin/bwrap", nil, []string{"8080-8090"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !containsSeq(args, "-t", "8080-8090") {
		t.Errorf("expected -t 8080-8090\nfull args: %v", args)
	}
}

func TestBuildPastaArgsInvalidPorts(t *testing.T) {
	_, err := buildPastaArgs("/usr/bin/bwrap", nil, []string{"not-a-port"}, nil)
	if err == nil {
		t.Error("expected error for invalid TCP port")
	}

	_, err = buildPastaArgs("/usr/bin/bwrap", nil, nil, []string{"80:443"})
	if err == nil {
		t.Error("expected error for invalid UDP port")
	}
}
