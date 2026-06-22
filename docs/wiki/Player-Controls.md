# Player Controls

`ghostshell play` and `ghostshell play-user` open a full-screen player when output is a terminal.

## Status bar format

```
 > 01:23 / 05:00 [####      ]  27%  1x   <-/-> seek  pgup scroll  g goto  spc play  q quit
```

| Part | Meaning |
|:-----|:--------|
| `>` | Playing (`\|\|` when paused) |
| `01:23 / 05:00` | Current position / total duration (MM:SS) |
| `[####      ]` | Progress bar — fills proportional to position |
| `27%` | Position as percentage |
| `1x` | Playback speed (`0.5x`, `2x`, `4x`, etc.) |

## Keyboard controls

| Key | Effect |
|:----|:-------|
| `space` | Pause / resume |
| `→` or `l` | Seek forward 5 seconds |
| `←` or `h` | Seek backward 5 seconds (re-renders recording up to that point) |
| `↑` or `+` | Double playback speed (max 64×) |
| `↓` or `-` | Halve playback speed (min 1/64×) |
| `g` | Go to time — bar changes to `goto:_`. Type `MM:SS` or plain seconds, Enter to jump, Esc to cancel. |
| `pgup` | Enter scroll view — browse past output; see [Scroll view](#scroll-view) below. |
| `b` | Toggle status bar visibility (full-height playback without the bar) |
| `0` | Restart from the beginning |
| `q` or `Ctrl-C` | Quit |

## Mouse controls

| Action | Effect |
|:-------|:-------|
| Click the `[####   ]` bar | Seek to the clicked position |
| Shift+click anywhere | Selects terminal text (does not seek) |

## Goto-time example

Press `g`, then type `2:30` and Enter:

```
 || 01:23 / 05:00 [####      ]  goto: 2:30_  (enter: jump  esc: cancel)
```

The player jumps to 2m 30s and resumes from there.

## Scroll view

Press `pgup` during playback to enter scroll view. The status bar changes to:

```
 [SCROLL] 42 lines   pgup/up/wheel: scroll up   any other key: exit
```

| Key | Effect |
|:----|:-------|
| `pgup` / `↑` / scroll wheel up | Scroll up 3 lines |
| `pgdn` / `↓` / scroll wheel down | Scroll down 3 lines |
| Any other key | Exit scroll view and return to player |

When scrolled back:

```
 [SCROLL] -9/42   pgdn/down/wheel: scroll down   any other key: exit
```

`-9/42` = 9 lines above the latest output, 42 lines total in the buffer.

## Speed reference

| Speed | How to reach from 1× |
|:------|:--------------------|
| 1/64× | `↓` six times |
| 1/4× | `↓` twice |
| 1× | default |
| 2× | `↑` once |
| 4× | `↑` twice |
| 16× | `↑` four times |
| 64× | `↑` six times (maximum) |

## Flags

| Flag | Default | Effect |
|:-----|:--------|:-------|
| `--speed N` | `1.0` | Playback speed multiplier |
| `--idle N` | `0` | Cap idle gaps to N seconds. `0` = exact original timing. Set `>0` to compress long pauses. Ignored in the interactive player — use seek instead. |
