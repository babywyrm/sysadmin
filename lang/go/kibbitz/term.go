package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

func main() {
	// Check if the system is Linux (for CentOS)
	if !isLinux() {
		fmt.Println("This script is intended for Linux systems.")
		os.Exit(1)
	}

	// Run the command to get the list of processes related to 'kibitz'
	cmd := exec.Command("pgrep", "-fl", "kibitz")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error running pgrep: %s\n", err)
		os.Exit(1)
	}

	// Extract PIDs from the output
	pids := extractPIDs(string(output))

	if len(pids) == 0 {
		fmt.Println("No 'kibitz' processes found.")
		os.Exit(0)
	}

	// Print the found PIDs
	fmt.Printf("Found 'kibitz' processes with PIDs: %v\n", pids)

	// Sleep for 30 seconds
	fmt.Println("Waiting for 30 seconds before terminating processes...")
	time.Sleep(30 * time.Second)

	// Terminate the processes
	for _, pid := range pids {
		terminateCommand := exec.Command("kill", pid)
		err := terminateCommand.Run()
		if err != nil {
			fmt.Printf("Error terminating process with PID %s: %s\n", pid, err)
		} else {
			fmt.Printf("Terminated process with PID %s\n", pid)
		}
	}
}

func isLinux() bool {
	return strings.Contains(strings.ToLower(runtime.GOOS), "linux")
}

func extractPIDs(output string) []string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	var pids []string
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			pids = append(pids, fields[1])
		}
	}
	return pids
}
