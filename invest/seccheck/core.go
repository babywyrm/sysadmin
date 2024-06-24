package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// getKernelVersion fetches the kernel version of the system
func getKernelVersion() string {
	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		log.Printf("Error fetching kernel version: %v", err)
		return ""
	}
	return strings.TrimSpace(string(out))
}

// getOpenPorts fetches a list of open ports
func getOpenPorts() string {
	out, err := exec.Command("ss", "-tuln").Output()
	if err != nil {
		log.Printf("Error fetching open ports: %v", err)
		return ""
	}
	return string(out)
}

// getRogueProcesses checks for rogue processes
func getRogueProcesses() string {
	out, err := exec.Command("ps", "aux").Output()
	if err != nil {
		log.Printf("Error fetching processes: %v", err)
		return ""
	}
	return string(out)
}

// getPendingUpdates checks for pending package updates
func getPendingUpdates() (string, int) {
	var out []byte
	var err error
	var totalUpdates int

	// Check if yum or dnf is available (CentOS/RHEL)
	if _, err = exec.LookPath("yum"); err == nil {
		cmd := exec.Command("bash", "-c", "yum check-update -q | sed 's/Security:\\ //g' | cut -d ' ' -f 1 | grep -v -E '^$' | sed ':a;N;$!ba;s/\\n/,\\ /g'")
		out, err = cmd.CombinedOutput()
		if err != nil {
			log.Printf("Error fetching pending updates using yum: %v", err)
			return "", 0
		}
	} else if _, err = exec.LookPath("apt"); err == nil {
		// Use apt for other systems like Debian/Ubuntu
		cmd := exec.Command("bash", "-c", "apt list --upgradeable | tail -n +2 | cut -d'/' -f1 | cut -d' ' -f1 | grep -v -E '^$'")
		out, err = cmd.CombinedOutput()
		if err != nil {
			log.Printf("Error fetching pending updates using apt: %v", err)
			return "", 0
		}
	} else {
		log.Println("Neither yum nor apt found on the system")
		return "", 0
	}

	// Count the number of pending updates
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		totalUpdates++
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error scanning pending updates output: %v", err)
	}

	// Log the total number of pending updates
	log.Printf("Pending Updates:\n%s", strings.TrimSpace(string(out)))

	// Return the formatted output and total count
	return strings.TrimSpace(string(out)), totalUpdates
}

// checkPendingKernel checks if a system restart is needed due to a pending kernel update
func checkPendingKernel() (bool, string, string, time.Time) {
	files, err := os.ReadDir("/boot")
	if err != nil {
		log.Printf("Error reading /boot directory: %v", err)
		return false, "", "", time.Time{}
	}

	var latestKernelTime time.Time
	var latestKernelName string

	for _, file := range files {
		if strings.HasPrefix(file.Name(), "vmlinuz-") {
			// Extract kernel version from file name
			fileKernel := strings.TrimPrefix(file.Name(), "vmlinuz-")
			fileKernel = strings.TrimSuffix(fileKernel, ".el7.x86_64") // Adjust this suffix as per your system's kernel format

			// Get the modification time of the kernel file
			fileInfo, err := file.Info()
			if err != nil {
				log.Printf("Error getting file info for %s: %v", file.Name(), err)
				continue
			}
			modTime := fileInfo.ModTime()

			// Compare with the latest found kernel
			if latestKernelTime.IsZero() || modTime.After(latestKernelTime) {
				latestKernelTime = modTime
				latestKernelName = fileKernel
			}
		}
	}

	if latestKernelName != "" {
		log.Printf("Newest kernel found in /boot, modified on %s", latestKernelTime.String())

		// Compare with the currently running kernel
		currentKernel := getKernelVersion()
		log.Printf("Kernel Version: %s", currentKernel)

		if latestKernelName != currentKernel {
			return true, currentKernel, latestKernelName, latestKernelTime
		}
	}

	return false, "", "", time.Time{}
}

// reportToServer sends the collected data to a central server
func reportToServer(data string) error {
	conn, err := net.Dial("tcp", "central-server:6699")
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = fmt.Fprintln(conn, data)
	return err
}

func main() {
	// Set up logging to a file
	logFile, err := os.OpenFile("seccheck.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	// Get system information
	openPorts := getOpenPorts()
	rogueProcesses := getRogueProcesses()
	pendingUpdates, totalUpdates := getPendingUpdates()
	restartNeeded, currentKernel, latestKernel, latestKernelTime := checkPendingKernel()

	// Prepare report
	restartAdvisory := ""
	latestKernelInfo := ""
	if restartNeeded {
		restartAdvisory = fmt.Sprintf("System restart required for new kernel (current kernel installed on %s)", currentKernel)
		latestKernelInfo = fmt.Sprintf("\nLatest vmlinuz Kernel: %s (modified on %s)", latestKernel, latestKernelTime.String())
	}

	report := fmt.Sprintf("Open Ports:\n%s\n\nRogue Processes:\n%s\n\nPending Updates:\n%s\n\n%s%s\n",
		openPorts, rogueProcesses, pendingUpdates, restartAdvisory, latestKernelInfo)

	// Log the report
	log.Println(report)

	// Log total number of pending updates
	log.Printf("Total number of pending updates: %d\n", totalUpdates)

	// Print the current kernel version
	log.Printf("Current Kernel Version: %s\n", currentKernel)

	// Uncomment the following lines to send the report to the server
	// if err := reportToServer(report); err != nil {
	// 	log.Printf("Error reporting to server: %v", err)
	// }
}
