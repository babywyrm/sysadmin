#!/bin/bash

# ==============================================================================
# modern_timer.sh
#
# A modern, feature-rich command-line timer and progress bar written in Bash.
# Overhaul of an original script to use named arguments, improve readability,
# and add new features.
# ==============================================================================

# --- Default Values ---
DEFAULT_DURATION=10      # seconds
DEFAULT_WIDTH=80         # columns
DEFAULT_REPEAT=1
DEFAULT_SOUND="beep"     # options: beep, alarm, mute
DEFAULT_CHAR="#"
DEFAULT_MESSAGE="Progress"

# --- Color Codes for Output ---
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# --- Function Definitions ---

# Displays the help message and exits.
usage() {
    echo "Usage: $0 [-t seconds] [-c columns] [-r count|inf] [-s mode] [-m message] [-p char]"
    echo
    echo "A command-line timer with a progress bar."
    echo
    echo "Options:"
    echo "  -t DURATION   Duration of the timer in seconds. (Default: ${DEFAULT_DURATION})"
    echo "  -c WIDTH      Width of the progress bar in columns. (Default: ${DEFAULT_WIDTH})"
    echo "  -r REPEAT     Number of times to repeat the timer, or 'inf' for infinite. (Default: ${DEFAULT_REPEAT})"
    echo "  -s SOUND_MODE Sound to play on completion: 'beep', 'alarm', or 'mute'. (Default: ${DEFAULT_SOUND})"
    echo "  -m MESSAGE    Message to display next to the progress bar. (Default: '${DEFAULT_MESSAGE}')"
    echo "  -p CHARACTER  Character to use for the progress bar. (Default: '${DEFAULT_CHAR}')"
    echo "  -h            Display this help message and exit."
    echo
    echo "Example: $0 -t 30 -m \"Compiling assets...\" -s alarm"
}

# Renders the progress bar to the console.
# Arguments: $1=current_step, $2=total_steps, $3=width, $4=message, $5=progress_char
display_progress() {
    local current_step=$1
    local total_steps=$2
    local width=$3
    local message=$4
    local progress_char=$5

    # Calculate percentage completion
    local percent=$((current_step * 100 / total_steps))

    # Calculate the number of filled characters in the bar
    local filled_len=$((width * current_step / total_steps))

    # Create the bar strings using printf for clean padding
    local filled_bar
    filled_bar=$(printf "%${filled_len}s" | tr ' ' "${progress_char}")
    local empty_bar
    empty_bar=$(printf "%$((width - filled_len))s")

    # Print the progress bar, message, and percentage. \r returns to the start of the line.
    printf "\r${YELLOW}[%s%s]${NC} ${GREEN}%3d%%${NC} | ${message}" "${filled_bar}" "${empty_bar}" "${percent}"
}

# Plays a sound based on the selected mode.
# Argument: $1=sound_mode
play_sound() {
    local mode=$1
    # Check if speaker-test command exists
    if ! command -v speaker-test &> /dev/null; then
        # Fallback to a simple terminal bell if speaker-test is not available
        if [[ "$mode" != "mute" ]]; then
            echo -e "\a"
        fi
        return
    fi

    case "$mode" in
        beep)
            # A single, short beep
            ( speaker-test -t sine -f 2000 >/dev/null 2>&1 ) &
            local pid=$!
            sleep 0.2s
            kill -9 "$pid" >/dev/null 2>&1
            ;;
        alarm)
            # A series of beeps to act as an alarm
            for _ in {1..4}; do
                ( speaker-test -t sine -f 2000 >/dev/null 2>&1 ) &
                local pid=$!
                sleep 0.15s
                kill -9 "$pid" >/dev/null 2>&1
            done
            ;;
        mute)
            # Do nothing for mute mode
            ;;
    esac
}

# --- Main Script Logic ---

# Set variables to default values
duration=${DEFAULT_DURATION}
width=${DEFAULT_WIDTH}
repeat_count=${DEFAULT_REPEAT}
sound_mode=${DEFAULT_SOUND}
message=${DEFAULT_MESSAGE}
progress_char=${DEFAULT_CHAR}

# Parse command-line options using getopts
while getopts ":t:c:r:s:m:p:h" opt; do
    case ${opt} in
        t) duration=${OPTARG} ;;
        c) width=${OPTARG} ;;
        r) repeat_count=${OPTARG} ;;
        s) sound_mode=${OPTARG} ;;
        m) message=${OPTARG} ;;
        p) progress_char=${OPTARG} ;;
        h) usage; exit 0 ;;
        \?) echo "Invalid option: -${OPTARG}" >&2; usage; exit 1 ;;
        :) echo "Option -${OPTARG} requires an argument." >&2; usage; exit 1 ;;
    esac
done

# --- Input Validation ---
if ! [[ "$duration" =~ ^[0-9]+$ ]] || [[ "$duration" -eq 0 ]]; then
    echo "Error: Duration (-t) must be a positive integer." >&2
    exit 1
fi
if ! [[ "$width" =~ ^[0-9]+$ ]] || [[ "$width" -lt 10 ]]; then
    echo "Error: Width (-c) must be an integer of at least 10." >&2
    exit 1
fi
if ! [[ "$sound_mode" =~ ^(beep|alarm|mute)$ ]]; then
    echo "Error: Sound mode (-s) must be 'beep', 'alarm', or 'mute'." >&2
    exit 1
fi

# --- Timer Execution Loop ---
run_loop() {
    echo "Starting timer: ${duration}s | Width: ${width} | Sound: ${sound_mode} | Message: ${message}"
    
    # The main timer loop
    for ((i = 0; i <= duration; i++)); do
        display_progress "$i" "$duration" "$width" "$message" "$progress_char"
        sleep 1
    done
    
    # Play the sound upon completion
    play_sound "$sound_mode"
    
    # Print a newline to move past the progress bar
    echo
}

# Handle repetitions
if [[ "$repeat_count" == "inf" ]]; then
    echo "Running in infinite mode. Press Ctrl+C to exit."
    while true; do
        run_loop
    done
else
    if ! [[ "$repeat_count" =~ ^[0-9]+$ ]]; then
        echo "Error: Repeat count (-r) must be a positive integer or 'inf'." >&2
        exit 1
    fi
    for ((j = 1; j <= repeat_count; j++)); do
        if [[ "$repeat_count" -gt 1 ]]; then
            echo -e "\n--- Running timer, iteration ${j} of ${repeat_count} ---"
        fi
        run_loop
    done
fi

echo -e "${GREEN}Timer finished.${NC}"
