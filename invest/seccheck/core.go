package main

import (
    "bufio"
    "encoding/json"
    "fmt"
    "log"
    "net"
    "os"
    "os/exec"
    "strings"
    "time"

    "github.com/mattn/go-isatty"
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

// getUptime fetches the system uptime
func getUptime() string {
    out, err := exec.Command("uptime").Output()
    if err != nil {
        log.Printf("Error fetching uptime: %v", err)
        return ""
    }
    return strings.TrimSpace(string(out))
}

// getPendingUpdates checks for pending package updates
func getPendingUpdates() int {
    var totalUpdates int

    // Check if yum or dnf is available (CentOS/RHEL)
    if _, err := exec.LookPath("yum"); err == nil {
        cmd := exec.Command("bash", "-c", "yum check-update -q | sed 's/Security:\\ //g' | cut -d ' ' -f 1 | grep -v -E '^$' | sed ':a;N;$!ba;s/\\n/,\\ /g'")
        out, err := cmd.CombinedOutput()
        if err != nil {
            log.Printf("Error fetching pending updates using yum: %v", err)
            return 0
        }
        scanner := bufio.NewScanner(strings.NewReader(string(out)))
        for scanner.Scan() {
            totalUpdates++
        }
        if err := scanner.Err(); err != nil {
            log.Printf("Error scanning pending updates output: %v", err)
        }
    } else if _, err := exec.LookPath("apt"); err == nil {
        // Use apt for other systems like Debian/Ubuntu
        cmd := exec.Command("bash", "-c", "apt list --upgradeable | tail -n +2 | cut -d'/' -f1 | cut -d' ' -f1 | grep -v -E '^$'")
        out, err := cmd.CombinedOutput()
        if err != nil {
            log.Printf("Error fetching pending updates using apt: %v", err)
            return 0
        }
        scanner := bufio.NewScanner(strings.NewReader(string(out)))
        for scanner.Scan() {
            totalUpdates++
        }
        if err := scanner.Err(); err != nil {
            log.Printf("Error scanning pending updates output: %v", err)
        }
    } else {
        log.Println("Neither yum nor apt found on the system")
        return 0
    }

    return totalUpdates
}

// checkPendingKernel checks if a system restart is needed due to a pending kernel update
func checkPendingKernel() (bool, string, time.Time) {
    files, err := os.ReadDir("/boot")
    if err != nil {
        log.Printf("Error reading /boot directory: %v", err)
        return false, "", time.Time{}
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
            return true, latestKernelName, latestKernelTime
        }
    }

    return false, "", time.Time{}
}

// getOpenPorts fetches a list of open TCP ports in LISTEN state
func getOpenPorts() []string {
    out, err := exec.Command("ss", "-tuln").Output()
    if err != nil {
        log.Printf("Error fetching open ports: %v", err)
        return nil
    }

    var ports []string
    scanner := bufio.NewScanner(strings.NewReader(string(out)))
    for scanner.Scan() {
        line := scanner.Text()
        if strings.Contains(line, "LISTEN") {
            ports = append(ports, line)
        }
    }

    if err := scanner.Err(); err != nil {
        log.Printf("Error scanning open ports output: %v", err)
    }

    return ports
}

// getRogueProcesses fetches processes related to python, perl, bash, and docker
func getRogueProcesses() []string {
    out, err := exec.Command("ps", "aux").Output()
    if err != nil {
        log.Printf("Error fetching processes: %v", err)
        return nil
    }

    var processes []string
    scanner := bufio.NewScanner(strings.NewReader(string(out)))
    for scanner.Scan() {
        line := scanner.Text()
        if strings.Contains(line, "python") || strings.Contains(line, "perl") || strings.Contains(line, "bash") || strings.Contains(line, "docker") {
            processes = append(processes, line)
        }
    }

    if err := scanner.Err(); err != nil {
        log.Printf("Error scanning processes output: %v", err)
    }

    return processes
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
    hostname, _ := os.Hostname()
    uptime := getUptime()
    restartNeeded, latestKernel, latestKernelTime := checkPendingKernel()
    pendingUpdates := getPendingUpdates()
    openPorts := getOpenPorts()
    rogueProcesses := getRogueProcesses()

    // Create the JSON structure
    data := map[string]interface{}{
        "hostname":          hostname,
        "uptime":            uptime,
        "pending_kernel":    latestKernel,
        "kernel_install_time": latestKernelTime.Format(time.RFC3339),
        "pending_updates":   pendingUpdates,
        "open_ports":        openPorts,
        "rogue_processes":   rogueProcesses,
    }

    if restartNeeded {
        data["reboot_required"] = true
    }

    // Convert to JSON
    jsonData, err := json.MarshalIndent(data, "", "  ")
    if err != nil {
        log.Fatalf("Error marshaling data to JSON: %v", err)
    }

    // Log the final information
    log.Println(string(jsonData))

    // Print to console if run from console
    if isatty.IsTerminal(os.Stdout.Fd()) {
        fmt.Println(string(jsonData))
    }

    // Uncomment the following lines to send the report to the server
    // if err := reportToServer(string(jsonData)); err != nil {
    //     log.Printf("Error reporting to server: %v", err)
    // }
}

