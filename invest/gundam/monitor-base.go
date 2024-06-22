
package main

import (
    "fmt"
    "io/ioutil"
    "net"
    "os/exec"
    "strings"
)

// GetKernelVersion fetches the kernel version of the system
func getKernelVersion() string {
    out, err := exec.Command("uname", "-r").Output()
    if err != nil {
        fmt.Println("Error fetching kernel version:", err)
        return ""
    }
    return strings.TrimSpace(string(out))
}

// GetOpenPorts fetches a list of open ports
func getOpenPorts() string {
    out, err := exec.Command("ss", "-tuln").Output()
    if err != nil {
        fmt.Println("Error fetching open ports:", err)
        return ""
    }
    return string(out)
}

// GetRogueProcesses checks for rogue processes
func getRogueProcesses() string {
    // This is a simple example; customize it as needed for your specific rogue process detection
    out, err := exec.Command("ps", "aux").Output()
    if err != nil {
        fmt.Println("Error fetching processes:", err)
        return ""
    }
    return string(out)
}

// CheckSensitiveDirs searches for suspicious files in sensitive directories
func checkSensitiveDirs(dirs []string) string {
    var result strings.Builder
    for _, dir := range dirs {
        files, err := ioutil.ReadDir(dir)
        if err != nil {
            result.WriteString(fmt.Sprintf("Error reading directory %s: %v\n", dir, err))
            continue
        }
        for _, file := range files {
            // This is a very basic check; you should implement more thorough checks
            if strings.Contains(file.Name(), "backdoor") || strings.Contains(file.Name(), "malware") {
                result.WriteString(fmt.Sprintf("Suspicious file found: %s/%s\n", dir, file.Name()))
            }
        }
    }
    return result.String()
}

// ReportToServer sends the collected data to a central server
func reportToServer(data string) {
    conn, err := net.Dial("tcp", "central-server:6699")
    if err != nil {
        fmt.Println("Error connecting to server:", err)
        return
    }
    defer conn.Close()
    fmt.Fprintln(conn, data)
}

func main() {
    kernelVersion := getKernelVersion()
    openPorts := getOpenPorts()
    rogueProcesses := getRogueProcesses()
    sensitiveDirs := []string{"/etc", "/tmp", "/var/tmp", "/usr/local", "/home"}
    suspiciousFiles := checkSensitiveDirs(sensitiveDirs)

    report := fmt.Sprintf("Kernel Version: %s\n\nOpen Ports:\n%s\n\nRogue Processes:\n%s\n\nSuspicious Files:\n%s\n",
        kernelVersion, openPorts, rogueProcesses, suspiciousFiles)
    
    reportToServer(report)
}
