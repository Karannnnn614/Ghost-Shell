package ansible

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"ghostshell/internal/cast"
	"ghostshell/internal/store"
)

// tmpDirRe extracts the ansible-tmp-<X> directory name from any SSH command.
// This is the correlation key: all 5 SSH sessions of one task share the same tmpdir.
var tmpDirRe = regexp.MustCompile(`(ansible-tmp-[\d.]+-\d+-\d+)`)

// ansiballRe extracts the module name from an AnsiballZ path.
var ansiballRe = regexp.MustCompile(`AnsiballZ_(\w+)\.py`)

// groupGap: task groups within this window form one inferred playbook run.
const groupGap = 120 * time.Second

// taskSession is one SSH session belonging to an Ansible task execution.
type taskSession struct {
	SessionID string
	Command   string
	Started   time.Time
	IsExec    bool // true = the AnsiballZ python exec (not mkdir/chmod/rm)
}

// incomingTask is one complete Ansible task (all SSH sessions correlated by tmpdir).
type incomingTask struct {
	Module   string
	TmpDir   string
	Started  time.Time
	Changed  bool
	Failed   bool
	Msg      string
	RC       int
	Sessions []taskSession
}

// incomingRun groups tasks that ran close together (same Ansible run).
type incomingRun struct {
	From  time.Time
	To    time.Time
	User  string
	Tasks []incomingTask
}

// readAnsibleResult parses the AnsiballZ execution session output and extracts
// changed/failed/msg/rc from the JSON result that AnsiballZ prints to stdout.
func readAnsibleResult(path string) (changed, failed bool, msg string, rc int) {
	snap, err := store.OpenCastSnapshot(path)
	if err != nil {
		return
	}
	defer snap.Close()

	br := bufio.NewReader(snap)
	if _, err := cast.ReadHeader(br); err != nil {
		return
	}

	var sb strings.Builder
	for {
		ev, err := cast.ReadEvent(br)
		if err != nil {
			break
		}
		sb.WriteString(ev.Data)
	}

	// AnsiballZ prints one JSON result line to stdout.
	lines := strings.Split(sb.String(), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if len(line) < 2 || line[0] != '{' {
			continue
		}
		var res struct {
			Changed bool   `json:"changed"`
			Failed  bool   `json:"failed"`
			Msg     string `json:"msg"`
			RC      int    `json:"rc"`
		}
		if err := json.Unmarshal([]byte(line), &res); err == nil {
			return res.Changed, res.Failed, res.Msg, res.RC
		}
	}
	return
}

// scanUserSessions returns all SSH sessions for a user in the central store,
// parsed into taskSession records, grouped by ansible-tmp dir.
// Returns: map[tmpDir][]taskSession
func scanUserSessions(user string) (map[string][]taskSession, error) {
	sessions, err := store.UserSessions(user)
	if err != nil {
		return nil, err
	}

	byTmp := map[string][]taskSession{}
	centralDir := store.UserDir(user)

	for _, name := range sessions {
		path := filepath.Join(centralDir, name)
		h, err := store.Header(path)
		if err != nil {
			continue
		}

		// Only look at commands that reference an ansible-tmp dir.
		m := tmpDirRe.FindStringSubmatch(h.Command)
		if m == nil {
			continue
		}
		tmpDir := m[1]

		// store.Started formats the header timestamp in local time, so parse it
		// back in the local location and normalise to UTC. This keeps all parsed
		// timestamps in UTC (matching ParseRun) instead of silently treating a
		// local-formatted string as UTC.
		started := store.Started(h)
		t, _ := time.ParseInLocation("2006-01-02 15:04:05", started, time.Local)
		t = t.UTC()

		sess := taskSession{
			SessionID: name,
			Command:   h.Command,
			Started:   t,
			IsExec:    ansiballRe.MatchString(h.Command) && strings.Contains(h.Command, "python"),
		}
		byTmp[tmpDir] = append(byTmp[tmpDir], sess)
	}
	return byTmp, nil
}

// buildIncomingTasks converts the tmp-dir-grouped sessions into tasks.
func buildIncomingTasks(byTmp map[string][]taskSession, user string, centralDir string) []incomingTask {
	var tasks []incomingTask

	for tmpDir, sessions := range byTmp {
		// Sort sessions by start time.
		sort.Slice(sessions, func(i, j int) bool {
			return sessions[i].Started.Before(sessions[j].Started)
		})

		// Find the AnsiballZ exec session for module name + result.
		var module string
		var changed, failed bool
		var msg string
		var rc int
		earliest := sessions[0].Started

		for _, s := range sessions {
			if s.IsExec {
				m := ansiballRe.FindStringSubmatch(s.Command)
				if m != nil {
					module = m[1]
				}
				path := filepath.Join(centralDir, s.SessionID)
				changed, failed, msg, rc = readAnsibleResult(path)
			}
			if s.Started.Before(earliest) {
				earliest = s.Started
			}
		}

		if module == "" {
			continue // no exec session found — skip (might be just cleanup)
		}

		tasks = append(tasks, incomingTask{
			Module:   module,
			TmpDir:   tmpDir,
			Started:  earliest,
			Changed:  changed,
			Failed:   failed,
			Msg:      msg,
			RC:       rc,
			Sessions: sessions,
		})
	}

	sort.Slice(tasks, func(i, j int) bool {
		return tasks[i].Started.Before(tasks[j].Started)
	})
	return tasks
}

// groupIntoRuns groups tasks by time proximity into inferred playbook runs.
func groupIntoRuns(tasks []incomingTask, user string) []incomingRun {
	if len(tasks) == 0 {
		return nil
	}
	var runs []incomingRun
	cur := incomingRun{From: tasks[0].Started, To: tasks[0].Started, User: user}
	for _, t := range tasks {
		if len(cur.Tasks) > 0 && t.Started.Sub(cur.To) > groupGap {
			runs = append(runs, cur)
			cur = incomingRun{From: t.Started, To: t.Started, User: user}
		}
		cur.Tasks = append(cur.Tasks, t)
		if t.Started.After(cur.To) {
			cur.To = t.Started
		}
	}
	if len(cur.Tasks) > 0 {
		runs = append(runs, cur)
	}
	return runs
}

// Incoming implements `ghostshell ansible incoming [--user U]`.
// Reads the central store SSH sessions, correlates by ansible-tmp dir,
// and shows grouped Ansible task executions.
func Incoming(args []string) error {
	userFilter := ""
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--user" {
			userFilter = args[i+1]
			break
		}
	}

	// Incoming correlates SSH sessions across the root-only central store, so it
	// is a root command. Reject non-root callers explicitly (defense-in-depth on
	// top of the store's 0700 perms) before touching any user's directory.
	if !isRoot() {
		return fmt.Errorf("permission denied: ghostshell ansible incoming reads the root-only central store %s and must be run as root", store.CentralDir())
	}

	var users []string
	if userFilter != "" {
		users = []string{userFilter}
	} else {
		u, err := store.Users()
		if err != nil {
			if os.IsPermission(err) || os.IsNotExist(err) {
				return fmt.Errorf("cannot read %s (run as root): %v", store.CentralDir(), err)
			}
			return err
		}
		users = u
	}

	anyFound := false
	for _, u := range users {
		centralDir := store.UserDir(u)
		byTmp, err := scanUserSessions(u)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ghostshell: %s: %v\n", u, err)
			continue
		}
		if len(byTmp) == 0 {
			continue
		}

		tasks := buildIncomingTasks(byTmp, u, centralDir)
		if len(tasks) == 0 {
			continue
		}

		runs := groupIntoRuns(tasks, u)
		anyFound = true

		for ri, run := range runs {
			ok, chg, fail := recap(run.Tasks)
			dur := run.To.Sub(run.From)
			fmt.Printf("\x1b[1m── run #%d  user=%-15s  %s  (%s)  tasks=%d ok=%d chg=%d fail=%d\x1b[0m\n",
				ri+1, sanitize(u),
				run.From.Format("2006-01-02 15:04:05"),
				humanDur(dur),
				len(run.Tasks), ok, chg, fail)

			for _, t := range run.Tasks {
				icon := statusIcon(taskStatus(t))
				// t.Msg is parsed from the AnsiballZ result JSON in the captured
				// session and is attacker-influenced: sanitize before slicing
				// and printing so it cannot inject terminal escapes.
				detail := ""
				if msg := sanitize(t.Msg); msg != "" {
					if len(msg) > 55 {
						detail = "  " + msg[:55] + "…"
					} else {
						detail = "  " + msg
					}
				}
				if t.RC != 0 {
					detail += fmt.Sprintf("  rc=%d", t.RC)
				}
				fmt.Printf("  %s %-28s  %s  ssh_sessions=%d%s\n",
					icon, sanitize(t.Module), t.Started.Format("15:04:05"),
					len(t.Sessions), detail)
			}
			fmt.Println()
		}
	}

	if !anyFound {
		fmt.Println("no incoming Ansible sessions found in central store")
		fmt.Println()
		fmt.Println("hint: Ansible ControlMaster multiplexes tasks — disable it so each")
		fmt.Println("      task creates a separate SSH session captured by ForceCommand:")
		fmt.Println()
		fmt.Println("      # per-run:")
		fmt.Println("      ANSIBLE_SSH_ARGS=\"-o ControlMaster=no -o ControlPersist=no\"")
		fmt.Println()
		fmt.Println("      # or in ansible.cfg:")
		fmt.Println("      [ssh_connection]")
		fmt.Println("      ssh_args = -o ControlMaster=no -o ControlPersist=no")
	}
	return nil
}

// recap counts tasks by outcome (failed takes precedence over changed, which
// takes precedence over ok) for a run's PLAY-RECAP-style summary line.
func recap(tasks []incomingTask) (ok, chg, fail int) {
	for _, t := range tasks {
		switch {
		case t.Failed:
			fail++
		case t.Changed:
			chg++
		default:
			ok++
		}
	}
	return ok, chg, fail
}

func taskStatus(t incomingTask) string {
	switch {
	case t.Failed:
		return "failed"
	case t.Changed:
		return "changed"
	default:
		return "ok"
	}
}
