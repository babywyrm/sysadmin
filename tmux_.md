Got it — let’s modernize and tighten up what you’ve got. I’ll break it into two pieces:

1. **Your HTB box setup script** — cleaned and fixed.
2. **A 2025-ready tmux cheat-sheet** — trimmed, reorganized, and with updated bindings/options.

---

## 🔧 Updated HTB Box Setup Script (2025 edition)

```bash
#!/usr/bin/env bash
# HTB box bootstrap script
# Usage: ./setup.sh <boxname> <ip>

BOX="$1"
IP="$2"

# Ensure we are in the HackTheBox directory
if [[ "$(basename "$PWD")" != "HackTheBox" ]]; then
    echo "[-] Must run from HackTheBox directory (currently in $(basename "$PWD"))" >&2
    exit 1
fi

# Validate arguments
if [[ -z "$BOX" || -z "$IP" ]]; then
    echo "[-] Usage: $0 <boxname> <ip>" >&2
    exit 1
fi

# Check host reachability
if ! ping -c2 -W1 "$IP" &>/dev/null; then
    echo "[-] $IP unreachable" >&2
    exit 1
fi

# Normalize name
BOXU="$(tr '[:lower:]' '[:upper:]' <<< ${BOX:0:1})${BOX:1}"

# Create workspace
mkdir -p "$BOXU"/{scan,exploit,tmp}
cd "$BOXU" || exit 1
echo -e "# Info for $BOXU\n# $BOXU:$IP\n" > info.txt

# Update /etc/hosts if missing
if ! grep -q "$BOX\.htb" /etc/hosts; then
    echo "$IP $BOX $BOXU $BOX.htb" | sudo tee -a /etc/hosts
fi

# Start tmux session with splits
tmux new -s "$BOXU" \; split-window -h \; split-window -v
```

✅ Changes made:

* Fixed the logic bug in the ping check.
* Explicit error messages with `[-]`.
* Safer quoting for variables.
* Uses `-W1` instead of `-t1` (portable ping timeout).
* Exits cleanly if `cd` fails.

---

## 📘 Modern tmux Cheat-Sheet (2025 edition)

### Sessions

* `tmux new -s NAME` → Create new session
* `tmux a -t NAME` → Attach to session
* `tmux ls` → List sessions
* `tmux kill-session -t NAME` → Kill session

### Windows

* `c` → New window
* `,` → Rename window
* `n / p` → Next / prev window
* `w` → List windows
* `&` → Kill window

### Panes

* `%` → Split vertically
* `"` → Split horizontally
* `o` → Toggle between panes
* `q` → Show pane numbers
* `x` → Kill pane
* `z` → Toggle zoom
* `Ctrl-b { / }` → Swap panes left/right
* `Ctrl-b Space` → Cycle layouts

### Navigation

* `Ctrl-b Up/Down/Left/Right` → Move to pane
* `last-window` → Switch back

### Resizing

* `Ctrl-b : resize-pane -U 5` → Resize up
* `Ctrl-b : resize-pane -D 5` → Resize down
* `Ctrl-b : resize-pane -L 5` → Resize left
* `Ctrl-b : resize-pane -R 5` → Resize right

### Copy Mode (vi-style)

* `[` → Enter copy mode
* `q` → Quit copy mode
* `Space` → Start selection
* `Enter` → Copy selection
* `p` → Paste

### Quality of Life

* `:setw synchronize-panes on` → Broadcast input to all panes
* `set -g mouse on` → Enable mouse (click to switch/resize)
* `set -g default-terminal "tmux-256color"` → True color
* `set -g status-justify centre` → Center status bar

---

⚡Pro tip: In 2025 most people set `prefix` to `Ctrl-a` (GNU Screen style) for convenience:

```bash
set -g prefix C-a
unbind C-b
bind C-a send-prefix
```

---

# .tmux.conf
##
##
```
#### GENERAL ####
# Use Ctrl-a as prefix (Screen-style)
unbind C-b
set -g prefix C-a
bind C-a send-prefix

# Truecolor + better terminal defaults
set -g default-terminal "tmux-256color"
set -as terminal-overrides ',xterm-256color:Tc'

# Start numbering windows/panes at 1
set -g base-index 1
setw -g pane-base-index 1

# Increase scrollback
set -g history-limit 10000

# Reload config quickly
bind r source-file ~/.tmux.conf \; display-message "Reloaded ~/.tmux.conf"

#### STATUS BAR ####
# Center window list
set -g status-justify centre

# Show session, window, and time
set -g status-left-length 40
set -g status-left '#[fg=green]#S #[fg=yellow]|'
set -g status-right '#[fg=cyan]%Y-%m-%d %H:%M '

# Highlight active window
setw -g window-status-current-format '#[fg=black,bg=yellow] #I:#W #[default]'

#### MOUSE ####
# Enable mouse for pane/window switching and resizing
set -g mouse on

#### PANES ####
# Split shortcuts
bind | split-window -h
bind - split-window -v

# Pane navigation with vim keys
bind -r h select-pane -L
bind -r j select-pane -D
bind -r k select-pane -U
bind -r l select-pane -R

# Resize with Shift + arrows
bind -r S-Left  resize-pane -L 5
bind -r S-Right resize-pane -R 5
bind -r S-Up    resize-pane -U 5
bind -r S-Down  resize-pane -D 5

# Toggle pane zoom
bind z resize-pane -Z

#### COPY MODE ####
# Use vi keys in copy mode
setw -g mode-keys vi

# Copy to system clipboard (macOS/Linux/X11)
bind -T copy-mode-vi y send -X copy-pipe-and-cancel "pbcopy"
bind -T copy-mode-vi Enter send -X copy-pipe-and-cancel "pbcopy"

#### QUALITY OF LIFE ####
# Sync panes (toggle)
bind S setw synchronize-panes \; display-message "Sync-panes: #{?synchronize-panes,ON,OFF}"

# Kill current window with confirmation
bind & confirm-before -p "Kill window #W? (y/n)" kill-window

# Kill current session with confirmation
bind X confirm-before -p "Kill session #S? (y/n)" kill-session


