package ansible

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"ghostshell/internal/config"
)

const sampleRun = `
{"type":"run","id":"20260527T120000-1234","playbook":"deploy.yml","user":"alice","started":1748337600,"controller":"ctrl.example.com"}
{"type":"play","name":"Install web server"}
{"type":"task","play":"Install web server","name":"install nginx","module":"ansible.builtin.dnf","host":"web1","status":"changed","rc":0,"t":1748337601,"stdout":"Installed: nginx\n","stderr":""}
{"type":"task","play":"Install web server","name":"install nginx","module":"ansible.builtin.dnf","host":"web2","status":"ok","rc":0,"t":1748337602}
{"type":"task","play":"Install web server","name":"fail intentionally","module":"ansible.builtin.command","host":"web1","status":"failed","rc":1,"t":1748337603,"stdout":"","stderr":"command not found\n"}
{"type":"task","play":"Install web server","name":"secret task","module":"ansible.builtin.shell","host":"web1","status":"ok","rc":0,"t":1748337604,"stdout":"<censored: no_log>","stderr":"<censored: no_log>"}
{"type":"task","play":"Install web server","name":"skip me","module":"ansible.builtin.debug","host":"web2","status":"skipped","t":1748337605}
{"type":"stats","host":"web1","ok":1,"changed":1,"failed":1,"unreachable":0,"skipped":0}
{"type":"stats","host":"web2","ok":2,"changed":0,"failed":0,"unreachable":0,"skipped":1}
`

func TestParseRun_basic(t *testing.T) {
	run, err := ParseRun(strings.NewReader(sampleRun))
	if err != nil {
		t.Fatalf("ParseRun error: %v", err)
	}

	if run.ID != "20260527T120000-1234" {
		t.Errorf("ID = %q, want 20260527T120000-1234", run.ID)
	}
	if run.Playbook != "deploy.yml" {
		t.Errorf("Playbook = %q, want deploy.yml", run.Playbook)
	}
	if run.User != "alice" {
		t.Errorf("User = %q, want alice", run.User)
	}
	if run.Controller != "ctrl.example.com" {
		t.Errorf("Controller = %q", run.Controller)
	}
}

func TestParseRun_plays(t *testing.T) {
	run, _ := ParseRun(strings.NewReader(sampleRun))
	if len(run.Plays) != 1 || run.Plays[0] != "Install web server" {
		t.Errorf("Plays = %v, want [Install web server]", run.Plays)
	}
}

func TestParseRun_tasks(t *testing.T) {
	run, _ := ParseRun(strings.NewReader(sampleRun))
	if len(run.Tasks) != 5 {
		t.Errorf("len(Tasks) = %d, want 5", len(run.Tasks))
	}
	// First task: changed
	if run.Tasks[0].Status != "changed" {
		t.Errorf("Tasks[0].Status = %q, want changed", run.Tasks[0].Status)
	}
	if run.Tasks[0].Host != "web1" {
		t.Errorf("Tasks[0].Host = %q, want web1", run.Tasks[0].Host)
	}
	if run.Tasks[0].Stdout != "Installed: nginx\n" {
		t.Errorf("Tasks[0].Stdout = %q", run.Tasks[0].Stdout)
	}
	// Failed task: has stderr
	if run.Tasks[2].Status != "failed" {
		t.Errorf("Tasks[2].Status = %q, want failed", run.Tasks[2].Status)
	}
	if run.Tasks[2].RC != 1 {
		t.Errorf("Tasks[2].RC = %d, want 1", run.Tasks[2].RC)
	}
	if !strings.Contains(run.Tasks[2].Stderr, "command not found") {
		t.Errorf("Tasks[2].Stderr = %q, want 'command not found'", run.Tasks[2].Stderr)
	}
}

func TestParseRun_noLog_censored(t *testing.T) {
	run, _ := ParseRun(strings.NewReader(sampleRun))
	// The no_log task has stdout/stderr set to "<censored: no_log>" by the plugin.
	// ParseRun must preserve it as-is (censoring is the plugin's responsibility).
	secret := run.Tasks[3]
	if secret.Name != "secret task" {
		t.Errorf("unexpected task name %q", secret.Name)
	}
	if !strings.Contains(secret.Stdout, "censored") {
		t.Errorf("Stdout should be censored, got %q", secret.Stdout)
	}
}

func TestParseRun_stats(t *testing.T) {
	run, _ := ParseRun(strings.NewReader(sampleRun))
	if run.TotalOK != 3 {
		t.Errorf("TotalOK = %d, want 3", run.TotalOK)
	}
	if run.TotalChanged != 1 {
		t.Errorf("TotalChanged = %d, want 1", run.TotalChanged)
	}
	if run.TotalFailed != 1 {
		t.Errorf("TotalFailed = %d, want 1", run.TotalFailed)
	}
	if run.TotalSkipped != 1 {
		t.Errorf("TotalSkipped = %d, want 1", run.TotalSkipped)
	}
	if _, ok := run.Stats["web1"]; !ok {
		t.Error("no stats for web1")
	}
}

func TestParseRun_hosts_sorted(t *testing.T) {
	run, _ := ParseRun(strings.NewReader(sampleRun))
	if len(run.Hosts) != 2 || run.Hosts[0] != "web1" || run.Hosts[1] != "web2" {
		t.Errorf("Hosts = %v, want [web1 web2]", run.Hosts)
	}
}

func TestParseRun_empty(t *testing.T) {
	run, err := ParseRun(strings.NewReader(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(run.Tasks) != 0 {
		t.Errorf("expected 0 tasks, got %d", len(run.Tasks))
	}
}

func TestParseRun_garbage_lines_skipped(t *testing.T) {
	input := `not json at all
{"type":"run","id":"abc-1","playbook":"x.yml","user":"u","started":1000,"controller":"h"}
another garbage line
{"type":"stats","host":"h1","ok":2}
`
	run, err := ParseRun(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if run.ID != "abc-1" {
		t.Errorf("ID = %q, want abc-1", run.ID)
	}
	if run.TotalOK != 2 {
		t.Errorf("TotalOK = %d, want 2", run.TotalOK)
	}
}

func TestTruncate(t *testing.T) {
	cap := config.Load().AnsibleOutputCap
	short := "hello"
	if truncate(short, cap) != short {
		t.Errorf("short string should not be truncated")
	}
	long := strings.Repeat("x", cap+100)
	got := truncate(long, cap)
	// Payload is capped; the result exceeds cap only by the marker length.
	if len(got) != cap+len(truncMarker) {
		t.Errorf("len(got) = %d, want %d", len(got), cap+len(truncMarker))
	}
	if !strings.Contains(got, "truncated") {
		t.Errorf("truncated string should contain 'truncated' marker")
	}
}

// TestTruncate_multibyte feeds multibyte runes whose byte cap lands mid-rune
// and asserts the truncated payload is still valid UTF-8 (rune-boundary safe).
func TestTruncate_multibyte(t *testing.T) {
	// '世' is 3 bytes. Choose a cap that cannot fall on a rune boundary for a
	// string made entirely of 3-byte runes (cap % 3 != 0) to force a back-walk.
	const r = "世"
	if len(r) != 3 {
		t.Fatalf("test assumption broken: len(%q) = %d", r, len(r))
	}
	s := strings.Repeat(r, 100) // 300 bytes
	for _, cap := range []int{10, 11, 13, 100, 299} {
		got := truncate(s, cap)
		if !utf8.ValidString(got) {
			t.Errorf("cap=%d: result is not valid UTF-8: %q", cap, got)
		}
		// Payload (got minus marker) must be <= cap and rune-aligned.
		payload := strings.TrimSuffix(got, truncMarker)
		if len(payload) > cap {
			t.Errorf("cap=%d: payload len %d exceeds cap", cap, len(payload))
		}
		if !utf8.ValidString(payload) {
			t.Errorf("cap=%d: payload not valid UTF-8: %q", cap, payload)
		}
	}
}

// A single task event whose JSON line is larger than the old fixed 256 KiB
// scanner buffer (but whose output is within the configured cap) must still
// parse: the scanner buffer is now sized from AnsibleOutputCap, so the run is
// not rejected wholesale with bufio.ErrTooLong. The output is cap-truncated.
func TestParseRun_largeLineWithinCapParses(t *testing.T) {
	// Pin a 64 KiB cap so the scanner buffer (sized from the cap) comfortably
	// exceeds the 300 KiB line below, while the 300 KiB output still overflows the
	// cap and is truncated. Independent of the build-time default cap.
	t.Setenv("GHOSTSHELL_ANSIBLE_OUTPUT_CAP", "65536")
	config.Reset()
	t.Cleanup(config.Reset)
	cap := config.Load().AnsibleOutputCap
	if cap != 65536 {
		t.Fatalf("cap setup failed: AnsibleOutputCap = %d, want 65536", cap)
	}
	// Build one task line whose stdout alone exceeds the cap and the old fixed
	// 256 KiB scanner buffer, so truncation kicks in and the cap-sized buffer is
	// what lets the line parse at all.
	big := strings.Repeat("A", 300*1024)
	line := `{"type":"task","play":"p","name":"big","module":"m","host":"h","status":"changed","rc":0,"t":1,"stdout":"` + big + `"}`
	input := `{"type":"run","id":"r-1","playbook":"x.yml","user":"u","started":1000,"controller":"c"}` + "\n" + line + "\n"

	run, err := ParseRun(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseRun on large line returned error (line should fit the cap-sized buffer): %v", err)
	}
	if len(run.Tasks) != 1 {
		t.Fatalf("len(Tasks) = %d, want 1 (large line was dropped/failed)", len(run.Tasks))
	}
	// Output is truncated to the configured cap (+ marker).
	got := run.Tasks[0].Stdout
	if len(got) > cap+len(truncMarker) {
		t.Errorf("stdout len = %d, want <= cap(%d)+marker", len(got), cap)
	}
	if !strings.Contains(got, "truncated") {
		t.Errorf("oversized stdout should carry the truncation marker")
	}
}

// A malformed (non-JSON or non-object) line must be skipped without aborting the
// parse: surrounding valid events are still applied. Complements
// TestParseRun_garbage_lines_skipped with interleaved malformed task lines.
func TestParseRun_malformedTaskLinesSkipped(t *testing.T) {
	input := strings.Join([]string{
		`{"type":"run","id":"r-2","playbook":"y.yml","user":"u","started":1,"controller":"c"}`,
		`{"type":"task" BROKEN JSON`, // malformed -> skipped
		`["not","an","object"]`,      // JSON array, not object -> skipped (first byte not '{')
		`{"type":"task","play":"p","name":"good","module":"m","host":"h","status":"ok","rc":0,"t":2}`, // valid
		``,    // blank -> skipped
		`   `, // whitespace -> skipped
	}, "\n")

	run, err := ParseRun(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseRun returned error on malformed-but-recoverable input: %v", err)
	}
	if run.ID != "r-2" {
		t.Errorf("run id = %q, want r-2", run.ID)
	}
	if len(run.Tasks) != 1 || run.Tasks[0].Name != "good" {
		t.Errorf("expected exactly the one valid task, got %+v", run.Tasks)
	}
}

// A non-root caller must not reach into another user's central ansible dir via
// `ansible show --user`. The central store is root-only, so --user is rejected
// with a clear, root-requiring error (defense-in-depth on top of file perms).
func TestAnsibleShowUserRequiresRoot(t *testing.T) {
	prev := geteuid
	geteuid = func() int { return 1000 } // unprivileged
	t.Cleanup(func() { geteuid = prev })

	err := Show([]string{"--user", "alice", "20260527T120000-1234"})
	if err == nil {
		t.Fatal("ansible show --user as non-root = nil error, want root requirement")
	}
	if !strings.Contains(err.Error(), "root") {
		t.Errorf("error = %q, want it to mention root", err.Error())
	}
}

// As root, `ansible list` consults the central store. With an empty central
// store it simply prints the header and returns nil (no panic, no error).
func TestAnsibleListAsRootEmptyStore(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GHOSTSHELL_CENTRAL_DIR", dir)
	t.Setenv("GHOSTSHELL_DIR", t.TempDir())
	config.Reset()
	t.Cleanup(config.Reset)
	prev := geteuid
	geteuid = func() int { return 0 } // root
	t.Cleanup(func() { geteuid = prev })

	if err := List(nil); err != nil {
		t.Errorf("List as root on empty store: %v", err)
	}
}

func TestValidAnsibleRunID_ingest(t *testing.T) {
	good := []string{
		"20260527T120000-1234",
		"20260527T120000-99999",
		"abc-123_T",
	}
	bad := []string{
		"",
		"ab",
		"../../etc/passwd",
		"run/id",
		strings.Repeat("a", 65),
		"has space",
	}
	// ValidRunID is exported; tested here via direct call.
	for _, id := range good {
		if !ValidRunID(id) {
			t.Errorf("expected valid: %q", id)
		}
	}
	for _, id := range bad {
		if ValidRunID(id) {
			t.Errorf("expected invalid: %q", id)
		}
	}
}

func TestValidRunID(t *testing.T) {
	cases := []struct {
		id   string
		want bool
	}{
		{"20260527T140300-12345", true},
		{"abc-def_GHI", true},
		{"", false},
		{"ab", false},
		{strings.Repeat("x", 65), false},
		{"has space", false},
		{"has/slash", false},
		{"has.dot", false},
	}
	for _, tc := range cases {
		if got := ValidRunID(tc.id); got != tc.want {
			t.Errorf("ValidRunID(%q) = %v, want %v", tc.id, got, tc.want)
		}
	}
}

func TestValidUser(t *testing.T) {
	cases := []struct {
		user string
		want bool
	}{
		{"alice", true},
		{"user.name", true}, // dots are fine for usernames (no separator)
		{"", false},
		{".", false},
		{"..", false},
		{"../etc", false},
		{"a/b", false},
		{`a\b`, false},
	}
	for _, tc := range cases {
		if got := validUser(tc.user); got != tc.want {
			t.Errorf("validUser(%q) = %v, want %v", tc.user, got, tc.want)
		}
	}
}

func TestSanitize(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "hello world", "hello world"},
		{"tab kept", "a\tb", "a\tb"},
		{"esc stripped", "a\x1b[31mRED\x1b[0mb", "a[31mRED[0mb"},
		{"osc stripped", "x\x1b]0;title\x07y", "x]0;titley"},
		{"newline dropped", "a\nb", "ab"},
		{"cr dropped", "a\rb", "ab"},
		{"nul dropped", "a\x00b", "ab"},
		{"del dropped", "a\x7fb", "ab"},
		{"c1 replaced", "a" + string(rune(0x9b)) + "b", "a" + string(rune(0xfffd)) + "b"}, // U+009B (8-bit CSI) replaced by U+FFFD
		{"unicode kept", "café-世界", "café-世界"},
	}
	for _, tc := range cases {
		if got := sanitize(tc.in); got != tc.want {
			t.Errorf("%s: sanitize(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
		if strings.ContainsRune(sanitize(tc.in), 0x1b) {
			t.Errorf("%s: sanitized output still contains ESC", tc.name)
		}
	}
}

func TestDuration_clampNegative(t *testing.T) {
	// Last task in slice order has T==0 (e.g. missing timestamp) but an earlier
	// task carries the real max T: Duration uses max T, not slice order.
	r := &Run{
		Started: time.Unix(1000, 0).UTC(),
		Tasks: []Task{
			{T: 1005},
			{T: 0}, // would yield a large negative span if used as "last"
		},
	}
	if got := r.Duration(); got != 5*time.Second {
		t.Errorf("Duration = %v, want 5s", got)
	}

	// A task before Started (clock skew) must clamp to 0, never negative.
	r2 := &Run{
		Started: time.Unix(2000, 0).UTC(),
		Tasks:   []Task{{T: 1990}},
	}
	if got := r2.Duration(); got != 0 {
		t.Errorf("Duration = %v, want 0 (clamped)", got)
	}

	// No tasks -> 0.
	if got := (&Run{Started: time.Unix(1000, 0).UTC()}).Duration(); got != 0 {
		t.Errorf("Duration (no tasks) = %v, want 0", got)
	}
}

func TestRecap(t *testing.T) {
	tasks := []incomingTask{
		{Failed: false, Changed: false}, // ok
		{Changed: true},                 // changed
		{Failed: true},                  // failed
		{Failed: true, Changed: true},   // failed wins over changed
		{Changed: false},                // ok
	}
	ok, chg, fail := recap(tasks)
	if ok != 2 || chg != 1 || fail != 2 {
		t.Errorf("recap = (ok=%d chg=%d fail=%d), want (2 1 2)", ok, chg, fail)
	}
	if o, c, f := recap(nil); o != 0 || c != 0 || f != 0 {
		t.Errorf("recap(nil) = (%d %d %d), want all zero", o, c, f)
	}
}

func TestGroupIntoRuns(t *testing.T) {
	base := time.Unix(1_000_000, 0).UTC()
	mk := func(offset time.Duration) incomingTask {
		return incomingTask{Started: base.Add(offset)}
	}
	// Two clusters: tasks within groupGap form one run; a gap > groupGap splits.
	tasks := []incomingTask{
		mk(0),
		mk(30 * time.Second),
		mk(60 * time.Second),
		mk(60*time.Second + groupGap + time.Second), // starts a new run
		mk(60*time.Second + groupGap + 10*time.Second),
	}
	runs := groupIntoRuns(tasks, "alice")
	if len(runs) != 2 {
		t.Fatalf("len(runs) = %d, want 2", len(runs))
	}
	if len(runs[0].Tasks) != 3 {
		t.Errorf("runs[0].Tasks = %d, want 3", len(runs[0].Tasks))
	}
	if len(runs[1].Tasks) != 2 {
		t.Errorf("runs[1].Tasks = %d, want 2", len(runs[1].Tasks))
	}
	if runs[0].User != "alice" {
		t.Errorf("runs[0].User = %q, want alice", runs[0].User)
	}
	// From/To bracket the cluster.
	if !runs[0].From.Equal(base) {
		t.Errorf("runs[0].From = %v, want %v", runs[0].From, base)
	}
	if !runs[0].To.Equal(base.Add(60 * time.Second)) {
		t.Errorf("runs[0].To = %v, want %v", runs[0].To, base.Add(60*time.Second))
	}
	if got := groupIntoRuns(nil, "alice"); got != nil {
		t.Errorf("groupIntoRuns(nil) = %v, want nil", got)
	}
}
