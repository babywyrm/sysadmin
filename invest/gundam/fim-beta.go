
go
package main

import (
    "crypto/sha256"
    "encoding/json"
    "fmt"
    "io"
    "io/ioutil"
    "net"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "time"
)

// FileEntry represents the metadata for a file or directory
type FileEntry struct {
    Path string `json:"path"`
    Hash string `json:"hash"`
}

// getKernelVersion fetches the kernel version of the system
func getKernelVersion() string {
    out, err := exec.Command("uname", "-r").Output()
    if err != nil {
        fmt.Println("Error fetching kernel version:", err)
        return ""
    }
    return strings.TrimSpace(string(out))
}

// getOpenPorts fetches a list of open ports
func getOpenPorts() string {
    out, err := exec.Command("ss", "-tuln").Output()
    if err != nil {
        fmt.Println("Error fetching open ports:", err)
        return ""
    }
    return string(out)
}

// getRogueProcesses checks for rogue processes
func getRogueProcesses() string {
    out, err := exec.Command("ps", "aux").Output()
    if err != nil {
        fmt.Println("Error fetching processes:", err)
        return ""
    }
    // Customize this logic to detect specific rogue processes
    return string(out)
}

// createBaseline creates a baseline of all files and directories in the given path
func createBaseline(path string) ([]FileEntry, error) {
    var baseline []FileEntry

    err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }

        hash := ""
        if !info.IsDir() {
            hash, err = hashFile(filePath)
            if err != nil {
                return err
            }
        }

        baseline = append(baseline, FileEntry{
            Path: filePath,
            Hash: hash,
        })
        return nil
    })

    if err != nil {
        return nil, err
    }

    return baseline, nil
}

// hashFile computes the SHA-256 hash of a file
func hashFile(filePath string) (string, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return "", err
    }
    defer file.Close()

    hash := sha256.New()
    if _, err := io.Copy(hash, file); err != nil {
        return "", err
    }

    return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// saveBaseline saves the baseline to a file
func saveBaseline(baseline []FileEntry, fileName string) error {
    data, err := json.Marshal(baseline)
    if err != nil {
        return err
    }

    return ioutil.WriteFile(fileName, data, 0644)
}

// loadBaseline loads the baseline from a file
func loadBaseline(fileName string) ([]FileEntry, error) {
    data, err := ioutil.ReadFile(fileName)
    if err != nil {
        return nil, err
    }

    var baseline []FileEntry
    if err := json.Unmarshal(data, &baseline); err != nil {
        return nil, err
    }

    return baseline, nil
}

// compareBaselines compares the current state with the baseline and detects changes
func compareBaselines(baseline []FileEntry, current []FileEntry) string {
    var result strings.Builder
    baselineMap := make(map[string]string)
    for _, entry := range baseline {
        baselineMap[entry.Path] = entry.Hash
    }

    for _, entry := range current {
        if hash, found := baselineMap[entry.Path]; !found {
            result.WriteString(fmt.Sprintf("New file detected: %s\n", entry.Path))
        } else if entry.Hash != hash {
            result.WriteString(fmt.Sprintf("File modified: %s\n", entry.Path))
        }
        delete(baselineMap, entry.Path)
    }

    for path := range baselineMap {
        result.WriteString(fmt.Sprintf("File deleted: %s\n", path))
    }

    return result.String()
}

// reportToServer sends the collected data to a central server
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
    // Create or load baseline
    var baseline []FileEntry
    var err error
    if _, err := os.Stat("baseline.json"); os.IsNotExist(err) {
        baseline, err = createBaseline("/etc")
        if err != nil {
            fmt.Println("Error creating baseline:", err)
            return
        }
        err = saveBaseline(baseline, "baseline.json")
        if err != nil {
            fmt.Println("Error saving baseline:", err)
            return
        }
    } else {
        baseline, err = loadBaseline("baseline.json")
        if err != nil {
            fmt.Println("Error loading baseline:", err)
            return
        }
    }

    // Periodically check for changes and report
    for {
        current, err := createBaseline("/etc")
        if err != nil {
            fmt.Println("Error creating current state:", err)
            continue
        }

        changes := compareBaselines(baseline, current)
        if changes != "" {
            report := fmt.Sprintf("Kernel Version: %s\n\nOpen Ports:\n%s\n\nRogue Processes:\n%s\n\nChanges Detected:\n%s\n",
                getKernelVersion(), getOpenPorts(), getRogueProcesses(), changes)
            reportToServer(report)
        }

        time.Sleep(1 * time.Hour) // Adjust the interval as needed
    }
}
