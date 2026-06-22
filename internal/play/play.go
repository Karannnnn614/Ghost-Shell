// Package play replays a recorded cast file to the terminal.
package play

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"ghostshell/internal/cast"
	"ghostshell/internal/store"
)

const (
	hideCursor  = "\x1b[?25l"     // DECTCEM hide
	showCursor  = "\x1b[?25h"     // DECTCEM show
	altEnter    = "\x1b[?1049h"   // enter alternate screen (saves prior screen)
	altExit     = "\x1b[?1049l"   // leave alternate screen (restores prior screen)
	clearScreen = "\x1b[2J\x1b[H" // clear and home
	resetRegion = "\x1b[r"        // clear scroll region
	// hostReset neutralizes the persistent terminal modes a malicious or merely
	// crashed recording can leave enabled — the replayed bytes are untrusted and
	// can contain arbitrary escape sequences. Leaving the alternate screen does
	// NOT undo these private modes, so they would otherwise bleed into the user's
	// shell. We reset, in order: SGR attributes (\x1b[0m, stop color/reverse
	// bleed); bracketed paste (?2004l, else pasted text is wrapped/eaten);
	// application cursor-keys (?1l) and keypad (ESC >, else arrows/numpad break);
	// mouse reporting (?1000l/?1006l, else clicks emit garbage); line wrap
	// (?7h, restore default autowrap); and the cursor is re-shown by showCursor
	// appended at the call sites. It is intentionally emitted on every exit path
	// (normal, quit, signal, panic-via-defer) so the host terminal is always sane.
	hostReset = "\x1b[0m\x1b[?2004l\x1b[?1l\x1b>\x1b[?1000l\x1b[?1006l\x1b[?7h"
	seekStep  = 5.0 // seconds per arrow-key seek
	maxSpeed  = 64.0
	minSpeed  = 1.0 / 64
	// maxWaitSeconds caps any single computed inter-event wait before it is
	// converted to a time.Duration. Untrusted cast timestamps could otherwise
	// produce an enormous (or, via overflow, negative) Duration that hangs the
	// player; an hour is far longer than any legitimate gap matters for replay.
	maxWaitSeconds = 3600.0
	// maxGotoLen caps the goto-prompt input buffer (e.g. "9999:59").
	maxGotoLen = 8
)

// Run replays a session. args is the play subcommand's argv (after "play").
func Run(args []string) error {
	fs := flag.NewFlagSet("play", flag.ContinueOnError)
	speed := fs.Float64("speed", 1.0, "playback speed multiplier")
	maxIdle := fs.Float64("idle", 0, "cap idle gaps to N seconds (default 0 = exact original timing)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: ghostshell play [--speed N] [--idle N] <file>")
	}
	if *speed <= 0 {
		return fmt.Errorf("--speed must be > 0")
	}

	// Resolve the argument: try it as given, then fall back to the store dir
	// so a bare filename from `ghostshell ls` works from any directory.
	name := fs.Arg(0)
	path := name
	if _, statErr := os.Stat(path); statErr != nil && !filepath.IsAbs(name) {
		if alt := filepath.Join(store.Dir(), name); fileExists(alt) {
			path = alt
		} else if cp, _, err := store.FindCentral(name); err == nil {
			path = cp
		}
	}
	return PlayFile(path, *speed, *maxIdle)
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// PlayFile replays the cast at path, transparently decrypting encrypted
// recordings. On an interactive terminal it shows a video-player-style status
// bar with playback controls; otherwise it plays straight through.
func PlayFile(path string, speed, maxIdle float64) error {
	if speed <= 0 {
		speed = 1.0
	}
	// Snapshot at open time: replaying an in-progress recording is bounded to
	// the data present when playback began (seeking needs a fixed length).
	rc, err := store.OpenCastSnapshot(path)
	if err != nil {
		return err
	}
	defer rc.Close()

	r := bufio.NewReader(rc)
	if _, err := cast.ReadHeader(r); err != nil {
		// An empty (0-byte) or header-truncated cast surfaces as io.EOF from the
		// header read; translate it to a clear message instead of a bare "EOF".
		if err == io.EOF {
			return fmt.Errorf("empty or invalid cast file: %s", path)
		}
		return err
	}
	events, err := readCastEvents(r)
	if err != nil {
		return err
	}
	events = sanitizeEvents(events)
	events = clampIdleGaps(events, maxIdle)

	interactive := term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
	if !interactive {
		// stdin may still be a tty (e.g. output piped). Suppress echo and drain
		// any terminal query responses so they don't leak onto the shell prompt.
		restore := beginReplayInput()
		err = playLinear(events, speed)
		drainTerminalInput()
		if restore != nil {
			restore()
		}
		return err
	}
	return playInteractive(events, speed)
}

// maxSkippableEvents bounds how many malformed event lines readCastEvents will
// skip before giving up. A handful of bad lines (a truncated/garbled tail, an
// editor-mangled middle line) shouldn't abort an otherwise-good replay, but a
// file that is mostly garbage is reported as an error rather than silently
// played as a near-empty session.
const maxSkippableEvents = 64

// readCastEvents reads all events, degrading gracefully on malformed lines:
// cast.ReadEvent has already consumed the offending line, so a parse error is
// skipped and reading continues with the next line. The skip is bounded so a
// wholly-corrupt body still surfaces an error instead of replaying as empty.
func readCastEvents(r *bufio.Reader) ([]cast.Event, error) {
	var events []cast.Event
	skipped := 0
	for {
		ev, err := cast.ReadEvent(r)
		if err == io.EOF {
			break
		}
		if err != nil {
			skipped++
			if skipped > maxSkippableEvents {
				return nil, fmt.Errorf("cast file is corrupt (%d+ malformed event lines): %w", skipped, err)
			}
			continue // bad line already consumed; resume at the next line
		}
		events = append(events, ev)
	}
	return events, nil
}

// sanitizeEvents makes event timestamps safe for time.Duration arithmetic.
// Cast files are untrusted input: a non-finite (NaN/+Inf/-Inf), negative, or
// wildly large Time would, once cast to a Duration, hang the player or make it
// busy-spin. We coerce every Time to a finite, non-negative, monotonically
// non-decreasing value. The slice is mutated in place (it is freshly built by
// readCastEvents and not shared).
func sanitizeEvents(events []cast.Event) []cast.Event {
	var last float64
	for i := range events {
		t := events[i].Time
		switch {
		case math.IsNaN(t):
			t = last // NaN carries no ordering; pin to previous timestamp
		case math.IsInf(t, 1):
			t = last + maxWaitSeconds // +Inf: treat as a single capped gap
		case math.IsInf(t, -1) || t < 0:
			t = 0
		}
		if t < last {
			t = last // enforce monotonic non-decreasing timeline
		}
		events[i].Time = t
		last = t
	}
	return events
}

// clampSeek bounds a seek target to the playable range [0, lastT]. Shared by
// the seek and chapter-jump paths so a target can never land outside the
// timeline (also coerces a NaN target, which fails both comparisons, to 0).
func clampSeek(target, lastT float64) float64 {
	if !(target > 0) { // false for negatives and NaN
		return 0
	}
	if target > lastT {
		return lastT
	}
	return target
}

// clampWait bounds a computed inter-event wait (in seconds) to a sane range
// before it is converted to a time.Duration, guarding against negative or huge
// values produced from untrusted timestamps.
func clampWait(seconds float64) time.Duration {
	if !(seconds > 0) { // also catches NaN
		return 0
	}
	if seconds > maxWaitSeconds {
		seconds = maxWaitSeconds
	}
	return time.Duration(seconds * float64(time.Second))
}

// clampIdleGaps returns a new event slice with inter-event gaps capped to
// maxIdle seconds. Timestamps are remapped so every downstream consumer
// (seek, chapters, clock) sees a consistent compressed timeline.
// Returns the original slice unchanged when maxIdle <= 0.
func clampIdleGaps(events []cast.Event, maxIdle float64) []cast.Event {
	if maxIdle <= 0 || len(events) == 0 {
		return events
	}
	out := make([]cast.Event, len(events))
	copy(out, events)
	var offset, last float64
	for i, ev := range out {
		gap := ev.Time - last
		last = ev.Time
		if gap > maxIdle {
			offset += gap - maxIdle
		}
		out[i].Time = ev.Time - offset
	}
	return out
}

// playLinear plays every event straight through with original timing, used
// when not in full interactive mode (e.g. stdin piped, or raw mode
// unavailable). When stdout is a tty the recorded bytes may contain
// alt-screen / cursor-hide / scroll-region sequences; we always wrap output in
// alt-screen enter/exit plus cursor-show and a scroll-region reset, restored on
// exit, so the user's shell screen and cursor are left intact regardless of
// what the recording emitted.
func playLinear(events []cast.Event, speed float64) error {
	if speed <= 0 {
		speed = 1.0
	}
	if term.IsTerminal(int(os.Stdout.Fd())) {
		_, _ = io.WriteString(os.Stdout, altEnter+clearScreen+showCursor)
		defer func() {
			// Scrub hostile private modes (bracketed paste, mouse, app-keypad,
			// SGR bleed) the untrusted recording may have enabled before leaving
			// the alt screen — leaving alt screen alone does not undo them.
			_, _ = io.WriteString(os.Stdout, resetRegion+altExit+hostReset+showCursor)
		}()
	}
	fmt.Fprintln(os.Stderr, "--- ghostshell replay start ---")
	defer fmt.Fprintln(os.Stderr, "\r\n--- ghostshell replay end ---")

	var last float64
	for _, ev := range events {
		gap := ev.Time - last
		last = ev.Time
		if gap > 0 {
			time.Sleep(clampWait(gap / speed))
		}
		if ev.Type == "o" {
			if _, err := io.WriteString(os.Stdout, ev.Data); err != nil {
				return err
			}
		}
	}
	return nil
}

// playInteractive replays inside a full-screen player frame: an alternate
// screen with the recording rendered in a scroll region above a persistent
// bottom transport bar (progress, time, speed). Controls: space pause/resume,
// arrows or h/l seek, up/down or +/- speed, g goto prompt, mouse-click the bar
// to seek, q quit. Playback holds on the final frame at the end until quit.
func playInteractive(events []cast.Event, speed float64) error {
	if speed <= 0 {
		speed = 1.0
	}
	fd := int(os.Stdin.Fd())
	old, err := term.MakeRaw(fd)
	if err != nil {
		// Can't drive controls without raw mode. Fall back to a straight replay,
		// keeping the echo-off + drain protection so terminal query responses
		// don't leak onto the shell prompt.
		r := beginReplayInput()
		e := playLinear(events, speed)
		drainTerminalInput()
		if r != nil {
			r()
		}
		return e
	}

	_, h := termSize()
	setRegion := func(height int) { fmt.Fprintf(os.Stdout, "\x1b[1;%dr", height-1) }

	// Enter the player frame: alt screen, clear, hide cursor, reserve the bottom
	// row for the transport bar by confining output to a scroll region above it.
	_, _ = io.WriteString(os.Stdout, altEnter+clearScreen+hideCursor)
	setRegion(h)
	_, _ = io.WriteString(os.Stdout, mouseEnable)

	var once sync.Once
	restore := func() {
		once.Do(func() {
			// Order: leave the player frame (scroll region, mouse, alt screen),
			// then hostReset+showCursor to scrub any hostile private modes the
			// untrusted recording left set, before handing the tty back to the
			// shell. Runs once on every exit path, including a panic via defer.
			_, _ = io.WriteString(os.Stdout, resetRegion+mouseDisable+altExit+hostReset+showCursor)
			_ = term.Restore(fd, old)
		})
	}
	defer restore()

	// MakeRaw disables ISIG, so Ctrl-C arrives as a byte (handled in-band).
	// Keep a SIGTERM handler so `kill` still restores the terminal.
	// Note: we only signal.Stop these channels and let GC reclaim them — never
	// close() a channel passed to signal.Notify, as a signal delivered during
	// shutdown would then panic with "send on closed channel".
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGTERM)
	defer signal.Stop(sigc)

	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	defer signal.Stop(winch)

	evc := make(chan event, 256)
	inputDone := make(chan struct{})
	inputExited := make(chan struct{})
	// Stop the input goroutine on any exit path and wait (bounded) for it to
	// release stdin (restore blocking mode) before we return, so the shell that
	// inherits the fd never sees it mid-restore and the goroutine can't steal a
	// byte after we've quit.
	defer func() {
		close(inputDone)
		select {
		case <-inputExited:
		case <-time.After(250 * time.Millisecond):
		}
	}()
	go func() {
		defer close(inputExited)
		readInput(evc, inputDone)
	}()

	// lastT is the timeline length: the time of the last *output* event. Using
	// the last event of any type would let trailing non-"o" events (e.g. input
	// records) push lastT past the final visible frame, and the end-of-stream
	// check below would then freeze before those tail events were consumed.
	// lastOut is the index of that last output event; output is exhausted once
	// idx passes it, which is what the auto-pause condition keys off.
	var lastT float64
	lastOut := -1
	for i := range events {
		if events[i].Type == "o" {
			lastT = events[i].Time
			lastOut = i
		}
	}
	idx := 0                   // index of the next event to emit
	vt := 0.0                  // playback time of the last emitted event
	anchor := time.Now()       // wall time vt was last synced to
	saveDepth := 0             // recording's open DECSC (\x1b7) count; bar heal waits for 0
	var saveOpenedAt time.Time // when saveDepth last went positive (heal decay)
	paused := false
	inGoto := false
	gotoBuf := ""
	listMode := false
	barHidden := false
	var chapters []chapter
	haveChapters := false
	listSel := 0
	barCol, barW, barRow := 0, 0, h

	// Scrollback state.
	var scrollBuf lineBuf
	scrollMode := false
	scrollOffset := 0
	var renderBuf *strings.Builder // non-nil during renderTo → redirects emit to buffer

	// frozen reports whether playback is held (any modal/paused state).
	frozen := func() bool { return paused || inGoto || listMode || scrollMode }

	// displayTime is vt interpolated by wall time while playing, so the clock
	// advances smoothly (including across long idle gaps) without mutating vt.
	displayTime := func() float64 {
		if frozen() {
			return vt
		}
		d := vt + time.Since(anchor).Seconds()*speed
		if d > lastT {
			d = lastT
		}
		return d
	}
	drawBar := func() {
		if barHidden {
			return
		}
		barCol, barW, barRow = drawStatus(displayTime(), lastT, speed, paused, inGoto, gotoBuf)
	}
	// safeDrawBar heals the bar only when the recording isn't mid save/restore,
	// so our cursor save/restore can't corrupt the recording's own (which can
	// span events, e.g. apt progress bars). A stale open save (truncated cast,
	// mismatched \x1b7) decays after 500ms so the clock can't freeze forever.
	safeDrawBar := func() {
		if saveDepth <= 0 || time.Since(saveOpenedAt) >= 500*time.Millisecond {
			drawBar()
		}
	}
	emit := func(data string) {
		if renderBuf != nil {
			renderBuf.WriteString(data)
		} else {
			_, _ = io.WriteString(os.Stdout, data)
		}
		scrollBuf.feed(data)
		d, reset := saveDelta(data)
		if reset { // RIS in the stream clears the save slot
			saveDepth = 0
			return
		}
		prev := saveDepth
		saveDepth += d
		if saveDepth < 0 {
			saveDepth = 0
		}
		if prev == 0 && saveDepth > 0 {
			saveOpenedAt = time.Now()
		}
	}
	emitForward := func(target float64) {
		for idx < len(events) && events[idx].Time <= target {
			if events[idx].Type == "o" {
				emit(events[idx].Data)
			}
			idx++
		}
	}
	// renderTo clears the viewport and replays from the start up to target.
	// Used for backward seeks, resizes, and exiting overlays; never RIS (that
	// would drop the alt screen and scroll region). Resets the scrollback buffer
	// so it matches the replayed output.
	//
	// TODO(perf): this is O(n) from event 0 on every backward seek/resize. A
	// safe incremental approach (periodic terminal-state snapshots to resume
	// from the nearest checkpoint) is non-trivial and left for a follow-up; the
	// full replay is correct and acceptable for typical recording sizes.
	renderTo := func(target float64) {
		var b strings.Builder
		b.WriteString(clearScreen)
		renderBuf = &b
		saveDepth = 0
		idx = 0
		scrollBuf = lineBuf{}
		emitForward(target)
		renderBuf = nil
		_, _ = io.WriteString(os.Stdout, b.String())
	}
	syncClock := func() {
		if !frozen() {
			vt = displayTime()
		}
		anchor = time.Now()
	}
	seek := func(target float64) {
		target = clampSeek(target, lastT)
		if target < vt {
			renderTo(target)
		} else {
			emitForward(target)
		}
		vt = target
		anchor = time.Now()
	}
	// drawScrollView renders the scrollback buffer in the viewport. Resets the
	// scroll region to full-screen, clears, prints buffered lines, then draws the
	// scroll indicator at the bottom row. drawBar is NOT called here; exitScroll
	// calls it after restoring the scroll region.
	drawScrollView := func() {
		w, hh := termSize()
		contentH := hh - 1 // reserve 1 row for scroll indicator
		if contentH < 1 {
			contentH = 1
		}
		total := len(scrollBuf.lines)

		end := total - scrollOffset
		if end > total {
			end = total
		}
		if end < 0 {
			end = 0
		}
		start := end - contentH
		if start < 0 {
			start = 0
		}

		var b strings.Builder
		b.WriteString(resetRegion + clearScreen + "\x1b[0m")
		for i := start; i < end; i++ {
			line := scrollBuf.lines[i]
			if visWidth(line) > w {
				line = truncLine(line, w)
			}
			// \x1b[0m before: start each line with default attributes
			// \x1b[0m\x1b[K after: reset SGR then erase trailing cells with
			// default background, preventing color bleed into unfilled columns
			b.WriteString("\x1b[0m" + line + "\x1b[0m\x1b[K\r\n")
		}
		_, _ = io.WriteString(os.Stdout, b.String())
		drawScrollBar(total, scrollOffset, hh)
	}

	enterScroll := func() {
		if scrollMode {
			return
		}
		syncClock()
		paused = true
		scrollMode = true
		scrollOffset = 0
		drawScrollView()
	}

	exitScroll := func() {
		scrollMode = false
		setRegion(h)
		renderTo(vt)
		drawBar()
	}

	scrollUp := func() {
		if !scrollMode {
			enterScroll()
			return
		}
		_, hh := termSize()
		contentH := hh - 1
		if contentH < 1 {
			contentH = 1
		}
		total := len(scrollBuf.lines)
		maxOff := total - contentH
		if maxOff < 0 {
			maxOff = 0
		}
		newOff := scrollOffset + scrollStep
		if newOff > maxOff {
			newOff = maxOff
		}
		scrollOffset = newOff
		drawScrollView()
	}

	scrollDown := func() {
		if !scrollMode {
			return
		}
		newOff := scrollOffset - scrollStep
		if newOff < 0 {
			newOff = 0
		}
		scrollOffset = newOff
		if scrollOffset == 0 {
			exitScroll()
			return
		}
		drawScrollView()
	}

	resize := func() {
		_, h = termSize()
		if scrollMode {
			drawScrollView()
			return
		}
		if barHidden {
			_, _ = io.WriteString(os.Stdout, resetRegion)
		} else {
			setRegion(h)
		}
		renderTo(displayTime())
	}
	// toggleBar shows/hides the transport bar. Hiding releases the reserved row
	// so the recording renders full-height; showing reclaims it.
	toggleBar := func() {
		syncClock()
		barHidden = !barHidden
		if barHidden {
			_, _ = io.WriteString(os.Stdout, resetRegion)
		} else {
			setRegion(h)
		}
		renderTo(vt)
		drawBar()
	}

	openGotoList := func() {
		if !haveChapters {
			chapters = buildChapters(events)
			haveChapters = true
		}
		syncClock()
		if len(chapters) == 0 {
			inGoto, gotoBuf = true, "" // no commands detected; fall back to time entry
			return
		}
		listMode = true
		listSel = chapterAt(chapters, vt)
		w, hh := termSize()
		drawChapterList(chapters, listSel, w, hh)
	}
	exitList := func(target float64, jump bool) {
		listMode = false
		if jump {
			vt = clampSeek(target, lastT)
		}
		anchor = time.Now()
		renderTo(vt) // always clear the menu and rebuild content to vt
		drawBar()
	}

	dispatchList := func(ev event) bool {
		redraw := func() {
			w, hh := termSize()
			drawChapterList(chapters, listSel, w, hh)
		}
		switch ev.kind {
		case evMouse:
			if ev.press {
				_, hh := termSize()
				_, top := chapterWindow(listSel, hh)
				if i := top + (ev.my - 2); ev.my >= 2 && i >= 0 && i < len(chapters) {
					listSel = i
					exitList(chapters[listSel].t, true) // single click jumps
				}
			}
		case evArrow:
			switch ev.b {
			case 'A':
				if listSel > 0 {
					listSel--
				}
				redraw()
			case 'B':
				if listSel < len(chapters)-1 {
					listSel++
				}
				redraw()
			}
		case evByte:
			switch ev.b {
			case 'k':
				if listSel > 0 {
					listSel--
				}
				redraw()
			case 'j':
				if listSel < len(chapters)-1 {
					listSel++
				}
				redraw()
			case 0x0d, 0x0a: // Enter — jump to the selected command
				exitList(chapters[listSel].t, true)
			case 't': // switch to manual time entry
				listMode = false
				inGoto, gotoBuf = true, ""
				renderTo(vt)
				drawBar()
			case 'q', 0x03: // back to the player
				exitList(0, false)
			}
		}
		return true
	}

	handleByte := func(b byte) bool {
		if inGoto {
			switch {
			case b == 0x0d || b == 0x0a: // Enter
				if t, ok := parseClock(gotoBuf); ok {
					seek(t)
				}
				inGoto, gotoBuf = false, ""
				anchor = time.Now()
			case b == 0x7f || b == 0x08: // Backspace
				if len(gotoBuf) > 0 {
					gotoBuf = gotoBuf[:len(gotoBuf)-1]
				}
			case (b >= '0' && b <= '9') || b == ':':
				if len(gotoBuf) < maxGotoLen { // cap input; "9999:59" fits in 8
					gotoBuf += string(b)
				}
			default: // any other key cancels the goto prompt
				inGoto, gotoBuf = false, ""
				anchor = time.Now()
			}
			return true
		}
		switch b {
		case 'q', 0x03: // q or Ctrl-C
			return false
		case ' ':
			if paused {
				paused = false
				anchor = time.Now()
			} else {
				syncClock()
				paused = true
			}
		case 'h':
			syncClock()
			seek(vt - seekStep)
		case 'l':
			syncClock()
			seek(vt + seekStep)
		case '+', '=':
			syncClock()
			speed = faster(speed)
		case '-', '_':
			syncClock()
			speed = slower(speed)
		case '0':
			seek(0)
		case 'g':
			openGotoList()
		case 'b':
			toggleBar()
		}
		return true
	}

	dispatch := func(ev event) bool {
		if listMode {
			return dispatchList(ev)
		}
		// Scroll mode: scroll keys navigate; any other key exits scroll mode.
		if scrollMode {
			switch ev.kind {
			case evScroll:
				if ev.up {
					scrollUp()
				} else {
					scrollDown()
				}
			default:
				exitScroll()
			}
			return true
		}
		switch ev.kind {
		case evScroll:
			if ev.up {
				scrollUp()
			} else {
				scrollDown()
			}
		case evMouse:
			if !inGoto && !barHidden && ev.press && ev.my == barRow && barW > 1 &&
				ev.mx >= barCol && ev.mx <= barCol+barW-1 {
				syncClock()
				frac := float64(ev.mx-barCol) / float64(barW-1)
				seek(frac * lastT)
			}
		case evArrow:
			if inGoto {
				return true
			}
			switch ev.b {
			case 'C':
				syncClock()
				seek(vt + seekStep)
			case 'D':
				syncClock()
				seek(vt - seekStep)
			case 'A':
				syncClock()
				speed = faster(speed)
			case 'B':
				syncClock()
				speed = slower(speed)
			}
		case evByte:
			return handleByte(ev.b)
		}
		return true
	}

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	drawBar()
	for {
		// At the end, hold on the final frame (auto-pause) until the user quits.
		// Key off output exhaustion (idx past the last "o" event), not the raw
		// slice length, so trailing non-output events can't freeze us early and
		// the clock still settles on the last visible frame's time.
		if !frozen() && idx > lastOut {
			paused = true
			vt = lastT
			drawBar()
		}
		if frozen() {
			select {
			case ev, ok := <-evc:
				if !ok || !dispatch(ev) {
					return nil
				}
			case <-sigc:
				return errors.New("terminated")
			case <-winch:
				resize()
				if listMode {
					w, hh := termSize()
					drawChapterList(chapters, listSel, w, hh)
				}
			}
			if !listMode && !scrollMode {
				drawBar()
			}
			continue
		}
		next := events[idx].Time
		fireAt := anchor.Add(clampWait((next - vt) / speed))
		wait := time.Until(fireAt)
		if wait < 0 {
			wait = 0
		}
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
			vt = next
			anchor = time.Now()
			if events[idx].Type == "o" {
				emit(events[idx].Data)
			}
			idx++
		case <-ticker.C:
			timer.Stop()
			safeDrawBar()
		case ev, ok := <-evc:
			timer.Stop()
			if !ok || !dispatch(ev) {
				return nil
			}
			if !listMode && !scrollMode {
				drawBar()
			}
		case <-sigc:
			timer.Stop()
			return errors.New("terminated")
		case <-winch:
			timer.Stop()
			resize()
			drawBar()
		}
	}
}

// saveDelta returns the net change in open cursor-save (DECSC \x1b7 / DECRC
// \x1b8) depth contained in data. Recordings sometimes split a save/restore
// pair across events; tracking the depth lets the bar avoid drawing between
// them (its own save/restore would otherwise clobber the recording's).
func saveDelta(s string) (delta int, reset bool) {
	for i := 0; i+1 < len(s); i++ {
		if s[i] == 0x1b {
			switch s[i+1] {
			case '7': // DECSC
				delta++
			case '8': // DECRC
				delta--
			case 'c': // RIS clears the save slot
				delta, reset = 0, true
			}
		}
	}
	return delta, reset
}

// beginReplayInput puts stdin in a no-echo, non-canonical mode (keeping signal
// keys like Ctrl-C working) so terminal query responses aren't echoed to the
// screen during a non-interactive replay. Returns a restore func, or nil if
// stdin isn't a tty.
func beginReplayInput() func() {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil
	}
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil
	}
	raw := *old
	raw.Lflag &^= unix.ECHO | unix.ICANON
	raw.Cc[unix.VMIN] = 0
	raw.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &raw); err != nil {
		return nil
	}
	restore := func() { _ = unix.IoctlSetTermios(fd, unix.TCSETS, old) }
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	stop := make(chan struct{})
	go func() {
		select {
		case <-sigc:
			restore()
			os.Exit(130)
		case <-stop:
		}
	}()
	// Stop signal delivery, then release the watcher goroutine via stop. We do
	// not close(sigc): closing a channel passed to signal.Notify risks a
	// "send on closed channel" panic if a signal races shutdown. GC reclaims it.
	return func() {
		signal.Stop(sigc)
		close(stop)
		restore()
	}
}

// drainTerminalInput discards bytes the terminal sent in reply to query
// sequences echoed during replay, so they don't leak onto the shell prompt.
// Assumes stdin is already in non-canonical mode (see beginReplayInput).
func drainTerminalInput() {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		return
	}
	defer func() { _ = unix.SetNonblock(fd, false) }()

	buf := make([]byte, 4096)
	deadline := time.Now().Add(120 * time.Millisecond)
	for time.Now().Before(deadline) {
		n, rerr := unix.Read(fd, buf)
		if n > 0 {
			continue // discard
		}
		if rerr == unix.EAGAIN || rerr == unix.EWOULDBLOCK {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		break
	}
}
