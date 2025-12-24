// Package osinfo allows access to operating system information
// such as name (distribution name in case of Linux), version, and architecture.
//
// BUILD & INTEGRATION INSTRUCTIONS:
//
// 1. Initialize a generic module (if not already done):
//    go mod init github.com/yourname/systats
//
// 2. Place this file in a folder named 'osinfo':
//    mkdir osinfo
//    mv osinfo.go osinfo/
//
// 3. Import and use in your main.go:
//    package main
//
//    import (
//        "fmt"
//        "your-module-path/osinfo"
//    )
//
//    func main() {
//        info := osinfo.NewOS()
//        fmt.Printf("OS: %s\nVersion: %s\nArch: %s\n", info.Name, info.Version, info.Arch)
//    }
//
// 4. Run:
//    go run main.go
//

package osinfo

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// OS contains operating system information.
type OS struct {
	Name    string
	Version string
	Arch    string
}

// NewOS creates a new OS info struct populated with current system data.
func NewOS() *OS {
	result := &OS{
		Name:    runtime.GOOS,
		Version: "unknown",
		Arch:    runtime.GOARCH,
	}

	switch runtime.GOOS {
	case "windows":
		result.Name = "Windows"
		result.Version = GetWindowsVersion()
	case "linux":
		distro, ver := GetLinuxVersion()
		if distro != "" {
			result.Name = distro
		}
		result.Version = ver
	case "darwin":
		result.Name = "macOS"
		result.Version = GetMacVersion()
	}

	return result
}

// GetWindowsVersion retrieves the Windows marketing version.
func GetWindowsVersion() string {
	// Map kernel versions to marketing names
	versionNumbers := map[string]string{
		`5\.0`:  "2000",
		`5\.1`:  "XP",
		`5\.2`:  "Server 2003",
		`6\.0`:  "Server 2008",
		`6\.1`:  "Server 2008 R2",
		`6\.2`:  "Server 2012",
		`6\.3`:  "Server 2012 R2",
		`10\.0`: "10",
	}

	// Use 'cmd /c ver' instead of opening an interactive shell.
	// This is faster and less prone to hanging.
	cmd := exec.Command("cmd", "/c", "ver")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "Unknown"
	}

	outputStr := string(out)

	for key, name := range versionNumbers {
		// Regex to find "Version X.X.XXXX"
		// We use slightly looser matching to account for localization differences
		re := regexp.MustCompile(`Version\s+` + key + `\.([0-9]+)`)
		
		if matches := re.FindStringSubmatch(outputStr); len(matches) > 1 {
			// Windows 10/11/Server Logic based on build number
			if name == "10" {
				buildNum := Str2Int(matches[1])
				// Windows 11 starts roughly at build 22000
				if buildNum >= 22000 {
					return "11"
				}
				// Distinguish Server 2016/2019/2022 from standard Win 10
				// Note: Accurate detection usually requires Registry checks (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\InstallationType)
				// This is a best-effort heuristic based on the original logic.
				if buildNum > 17134 {
					return "Server 2019/2022" 
				} else if buildNum > 14393 {
					return "Server 2016"
				}
				return "10"
			}
			return name
		}
	}

	return "Unknown"
}

// GetLinuxVersion retrieves the Linux distribution name and version ID.
func GetLinuxVersion() (name, version string) {
	const osReleasePath = "/etc/os-release"

	exists, err := PathExists(osReleasePath)
	if !exists || err != nil {
		return "Linux", "Unknown"
	}

	// Read file directly using native Go OS package (no external 'cat' command)
	content, err := os.ReadFile(osReleasePath)
	if err != nil {
		return "Linux", "Unknown"
	}

	data := string(content)

	// Helper to extract value by key (handling quotes)
	getValue := func(key string) string {
		// Look for KEY="Value" or KEY=Value
		re := regexp.MustCompile(`(?m)^` + key + `="?([^"\n]+)"?`)
		matches := re.FindStringSubmatch(data)
		if len(matches) > 1 {
			return matches[1]
		}
		return ""
	}

	name = getValue("ID")
	// Capitalize the first letter of the distro name for prettiness
	if len(name) > 1 {
		name = strings.Title(strings.ToLower(name))
	}
	
	version = getValue("VERSION_ID")

	return name, version
}

// GetMacVersion attempts to get macOS version using sw_vers
func GetMacVersion() string {
	cmd := exec.Command("sw_vers", "-productVersion")
	out, err := cmd.Output()
	if err != nil {
		return "Unknown"
	}
	return strings.TrimSpace(string(out))
}

// PathExists checks if a path exists.
func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, fmt.Errorf("os.Stat error: %w", err)
}

// Str2Int converts string to int (ignores errors, returns 0).
func Str2Int(value string) int {
	val, _ := strconv.Atoi(value)
	return val
}
