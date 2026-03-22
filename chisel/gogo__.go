package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ─── Config ───────────────────────────────────────────────────────────────────

type TunnelConfig struct {
	Name        string
	Description string
	Remotes     []string
}

type ServerConfig struct {
	Port    string
	Key     string
	Auth    string
	Reverse bool
	Proxy   string
}

// Default config — edit these or we can add YAML loading later
var serverConfig = ServerConfig{
	Port:    "8080",
	Key:     "private",
	Auth:    "user:pass",
	Reverse: true,
	Proxy:   "",
}

var tunnelConfigs = []TunnelConfig{
	{
		Name:        "ldap-dc01",
		Description: "Forward LDAP + Kerberos from DC01",
		Remotes:     []string{"R:389:127.0.0.1:389", "R:88:127.0.0.1:88"},
	},
	{
		Name:        "socks-victim",
		Description: "SOCKS5 proxy through victim",
		Remotes:     []string{"R:socks"},
	},
	{
		Name:        "smtp-relay",
		Description: "Forward SMTP port 25",
		Remotes:     []string{"R:25:127.0.0.1:25"},
	},
}

// ─── Tunnel State ─────────────────────────────────────────────────────────────

type TunnelStatus int

const (
	StatusStopped TunnelStatus = iota
	StatusConnecting
	StatusConnected
	StatusError
)

func (s TunnelStatus) String() string {
	switch s {
	case StatusStopped:
		return "STOPPED"
	case StatusConnecting:
		return "CONNECTING"
	case StatusConnected:
		return "CONNECTED"
	case StatusError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

type Tunnel struct {
	Config  TunnelConfig
	Status  TunnelStatus
	cmd     *exec.Cmd
	mu      sync.Mutex
	logs    []string
	Latency string
}

func (t *Tunnel) addLog(line string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	ts := time.Now().Format("15:04:05")
	t.logs = append(t.logs, fmt.Sprintf("[%s] %s", ts, line))
	if len(t.logs) > 100 {
		t.logs = t.logs[len(t.logs)-100:]
	}
}

func (t *Tunnel) GetLogs() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	cp := make([]string, len(t.logs))
	copy(cp, t.logs)
	return cp
}

// ─── Server State ─────────────────────────────────────────────────────────────

type Server struct {
	Status TunnelStatus
	cmd    *exec.Cmd
	mu     sync.Mutex
	logs   []string
}

func (s *Server) addLog(line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ts := time.Now().Format("15:04:05")
	s.logs = append(s.logs, fmt.Sprintf("[%s] %s", ts, line))
	if len(s.logs) > 100 {
		s.logs = s.logs[len(s.logs)-100:]
	}
}

func (s *Server) GetLogs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]string, len(s.logs))
	copy(cp, s.logs)
	return cp
}

// ─── Tea Messages ─────────────────────────────────────────────────────────────

type statusUpdateMsg struct {
	index  int // -1 = server
	status TunnelStatus
}

type logUpdateMsg struct{}

type tickMsg time.Time

// ─── Model ────────────────────────────────────────────────────────────────────

type view int

const (
	viewMain view = iota
	viewLogs
)

type model struct {
	server      *Server
	tunnels     []*Tunnel
	cursor      int
	currentView view
	logTarget   int // -1 = server logs
	chiselPath  string
	targetIP    string
	width       int
	height      int
}

func initialModel() model {
	tunnels := make([]*Tunnel, len(tunnelConfigs))
	for i, cfg := range tunnelConfigs {
		tunnels[i] = &Tunnel{Config: cfg, Status: StatusStopped}
	}

	chiselPath := "chisel"
	if path, err := exec.LookPath("chisel"); err == nil {
		chiselPath = path
	}

	targetIP := os.Getenv("CHISEL_TARGET")
	if targetIP == "" {
		targetIP = "10.10.10.10:8080"
	}

	return model{
		server:      &Server{Status: StatusStopped},
		tunnels:     tunnels,
		cursor:      0,
		currentView: viewMain,
		logTarget:   -1,
		chiselPath:  chiselPath,
		targetIP:    targetIP,
	}
}

// ─── Styles ───────────────────────────────────────────────────────────────────

var (
	styleBorder = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("62"))

	styleTitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("212")).
			PaddingLeft(1)

	styleSelected = lipgloss.NewStyle().
			Background(lipgloss.Color("62")).
			Foreground(lipgloss.Color("230")).
			PaddingLeft(1).
			PaddingRight(1)

	styleNormal = lipgloss.NewStyle().
			PaddingLeft(1).
			PaddingRight(1)

	styleConnected = lipgloss.NewStyle().
			Foreground(lipgloss.Color("82")).
			Bold(true)

	styleStopped = lipgloss.NewStyle().
			Foreground(lipgloss.Color("240"))

	styleConnecting = lipgloss.NewStyle().
			Foreground(lipgloss.Color("214")).
			Bold(true)

	styleError = lipgloss.NewStyle().
			Foreground(lipgloss.Color("196")).
			Bold(true)

	styleHelp = lipgloss.NewStyle().
			Foreground(lipgloss.Color("240")).
			PaddingLeft(1)

	styleLog = lipgloss.NewStyle().
			Foreground(lipgloss.Color("245")).
			PaddingLeft(1)

	styleHeader = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("99")).
			PaddingLeft(1)
)

func statusStyle(s TunnelStatus) lipgloss.Style {
	switch s {
	case StatusConnected:
		return styleConnected
	case StatusConnecting:
		return styleConnecting
	case StatusError:
		return styleError
	default:
		return styleStopped
	}
}

func statusDot(s TunnelStatus) string {
	switch s {
	case StatusConnected:
		return "●"
	case StatusConnecting:
		return "◌"
	case StatusError:
		return "✗"
	default:
		return "○"
	}
}

// ─── Init ─────────────────────────────────────────────────────────────────────

func (m model) Init() tea.Cmd {
	return tick()
}

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// ─── Update ───────────────────────────────────────────────────────────────────

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tickMsg:
		return m, tick()

	case statusUpdateMsg:
		if msg.index == -1 {
			m.server.mu.Lock()
			m.server.Status = msg.status
			m.server.mu.Unlock()
		} else if msg.index < len(m.tunnels) {
			m.tunnels[msg.index].mu.Lock()
			m.tunnels[msg.index].Status = msg.status
			m.tunnels[msg.index].mu.Unlock()
		}

	case tea.KeyMsg:
		switch m.currentView {
		case viewMain:
			return m.handleMainKeys(msg)
		case viewLogs:
			return m.handleLogKeys(msg)
		}
	}

	return m, nil
}

func (m model) handleMainKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		m.stopAll()
		return m, tea.Quit

	case "up", "k":
		if m.cursor > -1 {
			m.cursor--
		}

	case "down", "j":
		if m.cursor < len(m.tunnels)-1 {
			m.cursor++
		}

	case "s":
		// start server
		return m, m.startServerCmd()

	case "S":
		// stop server
		m.stopServer()

	case "enter", " ":
		// toggle selected tunnel
		if m.cursor >= 0 && m.cursor < len(m.tunnels) {
			t := m.tunnels[m.cursor]
			t.mu.Lock()
			status := t.Status
			t.mu.Unlock()
			if status == StatusStopped || status == StatusError {
				return m, m.startTunnelCmd(m.cursor)
			} else {
				m.stopTunnel(m.cursor)
			}
		}

	case "l":
		// view logs for selected
		m.currentView = viewLogs
		m.logTarget = m.cursor

	case "L":
		// view server logs
		m.currentView = viewLogs
		m.logTarget = -1

	case "p":
		// write proxychains config
		m.writeProxychains()

	case "a":
		// start all tunnels
		var cmds []tea.Cmd
		for i := range m.tunnels {
			cmds = append(cmds, m.startTunnelCmd(i))
		}
		return m, tea.Batch(cmds...)

	case "x":
		// stop all tunnels
		m.stopAll()
	}

	return m, nil
}

func (m model) handleLogKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc", "b":
		m.currentView = viewMain
	}
	return m, nil
}

// ─── View ─────────────────────────────────────────────────────────────────────

func (m model) View() string {
	switch m.currentView {
	case viewLogs:
		return m.renderLogs()
	default:
		return m.renderMain()
	}
}

func (m model) renderMain() string {
	var sb strings.Builder

	// Title bar
	sb.WriteString(styleTitle.Render("⚡ Chisel Orchestrator"))
	sb.WriteString("  ")
	sb.WriteString(styleHelp.Render(fmt.Sprintf("target: %s", m.targetIP)))
	sb.WriteString("\n\n")

	// Server section
	sb.WriteString(styleHeader.Render("SERVER"))
	sb.WriteString("\n")

	serverLine := fmt.Sprintf(
		"  %s  server :%s  auth:%s",
		statusDot(m.server.Status),
		serverConfig.Port,
		serverConfig.Auth,
	)
	sb.WriteString(statusStyle(m.server.Status).Render(serverLine))
	sb.WriteString("\n\n")

	// Tunnels section
	sb.WriteString(styleHeader.Render("TUNNELS"))
	sb.WriteString("\n")

	for i, t := range m.tunnels {
		t.mu.Lock()
		status := t.Status
		latency := t.Latency
		t.mu.Unlock()

		remotes := strings.Join(t.Config.Remotes, " ")
		latencyStr := ""
		if latency != "" {
			latencyStr = fmt.Sprintf(" (%s)", latency)
		}

		line := fmt.Sprintf(
			"  %s  [%d] %-20s %-12s %s%s",
			statusDot(status),
			i+1,
			t.Config.Name,
			status.String(),
			remotes,
			latencyStr,
		)

		if i == m.cursor {
			sb.WriteString(styleSelected.Render(line))
		} else {
			sb.WriteString(statusStyle(status).Render(line))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("\n")

	// Help bar
	help := []string{
		"↑/↓ navigate",
		"enter toggle tunnel",
		"s start server",
		"S stop server",
		"a start all",
		"x stop all",
		"l tunnel logs",
		"L server logs",
		"p write proxychains",
		"q quit",
	}
	sb.WriteString(styleHelp.Render(strings.Join(help, "  │  ")))
	sb.WriteString("\n")

	return sb.String()
}

func (m model) renderLogs() string {
	var sb strings.Builder

	var title string
	var logs []string

	if m.logTarget == -1 {
		title = "SERVER LOGS"
		logs = m.server.GetLogs()
	} else if m.logTarget < len(m.tunnels) {
		title = fmt.Sprintf("TUNNEL LOGS — %s", m.tunnels[m.logTarget].Config.Name)
		logs = m.tunnels[m.logTarget].GetLogs()
	}

	sb.WriteString(styleTitle.Render(fmt.Sprintf("⚡ %s", title)))
	sb.WriteString("\n\n")

	if len(logs) == 0 {
		sb.WriteString(styleLog.Render("  no logs yet..."))
	} else {
		// show last N lines based on terminal height
		maxLines := 40
		if m.height > 10 {
			maxLines = m.height - 8
		}
		start := 0
		if len(logs) > maxLines {
			start = len(logs) - maxLines
		}
		for _, line := range logs[start:] {
			sb.WriteString(styleLog.Render(line))
			sb.WriteString("\n")
		}
	}

	sb.WriteString("\n")
	sb.WriteString(styleHelp.Render("b / esc  back"))
	sb.WriteString("\n")

	return sb.String()
}

// ─── Chisel Process Management ────────────────────────────────────────────────

func (m model) startServerCmd() tea.Cmd {
	return func() tea.Msg {
		m.server.mu.Lock()
		if m.server.Status == StatusConnected || m.server.Status == StatusConnecting {
			m.server.mu.Unlock()
			return nil
		}
		m.server.Status = StatusConnecting
		m.server.mu.Unlock()

		args := []string{"server", "-p", serverConfig.Port}
		if serverConfig.Key != "" {
			args = append(args, "--key", serverConfig.Key)
		}
		if serverConfig.Auth != "" {
			args = append(args, "--auth", serverConfig.Auth)
		}
		if serverConfig.Reverse {
			args = append(args, "--reverse")
		}
		if serverConfig.Proxy != "" {
			args = append(args, "--proxy", serverConfig.Proxy)
		}

		cmd := exec.Command(m.chiselPath, args...)
		m.server.mu.Lock()
		m.server.cmd = cmd
		m.server.mu.Unlock()

		stdout, _ := cmd.StdoutPipe()
		stderr, _ := cmd.StderrPipe()

		if err := cmd.Start(); err != nil {
			m.server.addLog(fmt.Sprintf("ERROR: %s", err.Error()))
			return statusUpdateMsg{index: -1, status: StatusError}
		}

		m.server.addLog(fmt.Sprintf("started: %s %s", m.chiselPath, strings.Join(args, " ")))

		go func() {
			scanner := bufio.NewScanner(stdout)
			for scanner.Scan() {
				line := scanner.Text()
				m.server.addLog(line)
			}
		}()

		go func() {
			scanner := bufio.NewScanner(stderr)
			for scanner.Scan() {
				line := scanner.Text()
				m.server.addLog(line)
				if strings.Contains(line, "Listening") {
					m.server.mu.Lock()
					m.server.Status = StatusConnected
					m.server.mu.Unlock()
				}
			}
		}()

		go func() {
			cmd.Wait()
			m.server.mu.Lock()
			m.server.Status = StatusStopped
			m.server.mu.Unlock()
			m.server.addLog("server stopped")
		}()

		return statusUpdateMsg{index: -1, status: StatusConnected}
	}
}

func (m model) startTunnelCmd(index int) tea.Cmd {
	return func() tea.Msg {
		t := m.tunnels[index]
		t.mu.Lock()
		if t.Status == StatusConnected || t.Status == StatusConnecting {
			t.mu.Unlock()
			return nil
		}
		t.Status = StatusConnecting
		t.mu.Unlock()

		args := []string{"client"}
		if serverConfig.Auth != "" {
			args = append(args, "--auth", serverConfig.Auth)
		}
		args = append(args, m.targetIP)
		args = append(args, t.Config.Remotes...)

		cmd := exec.Command(m.chiselPath, args...)
		t.mu.Lock()
		t.cmd = cmd
		t.mu.Unlock()

		stdout, _ := cmd.StdoutPipe()
		stderr, _ := cmd.StderrPipe()

		if err := cmd.Start(); err != nil {
			t.addLog(fmt.Sprintf("ERROR: %s", err.Error()))
			return statusUpdateMsg{index: index, status: StatusError}
		}

		t.addLog(fmt.Sprintf("started: %s %s", m.chiselPath, strings.Join(args, " ")))

		go func() {
			scanner := bufio.NewScanner(stdout)
			for scanner.Scan() {
				line := scanner.Text()
				t.addLog(line)
			}
		}()

		go func() {
			scanner := bufio.NewScanner(stderr)
			for scanner.Scan() {
				line := scanner.Text()
				t.addLog(line)
				if strings.Contains(line, "Connected") {
					t.mu.Lock()
					t.Status = StatusConnected
					// parse latency
					if idx := strings.Index(line, "Latency"); idx != -1 {
						parts := strings.Fields(line[idx:])
						if len(parts) >= 2 {
							t.Latency = parts[1]
						}
					}
					t.mu.Unlock()
				}
			}
		}()

		go func() {
			cmd.Wait()
			t.mu.Lock()
			t.Status = StatusStopped
			t.Latency = ""
			t.mu.Unlock()
			t.addLog("tunnel stopped")
		}()

		return statusUpdateMsg{index: index, status: StatusConnecting}
	}
}

func (m model) stopServer() {
	m.server.mu.Lock()
	defer m.server.mu.Unlock()
	if m.server.cmd != nil && m.server.cmd.Process != nil {
		m.server.cmd.Process.Kill()
		m.server.cmd = nil
	}
	m.server.Status = StatusStopped
	m.server.addLog("server stopped by user")
}

func (m model) stopTunnel(index int) {
	t := m.tunnels[index]
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cmd != nil && t.cmd.Process != nil {
		t.cmd.Process.Kill()
		t.cmd = nil
	}
	t.Status = StatusStopped
	t.Latency = ""
	t.addLog("tunnel stopped by user")
}

func (m model) stopAll() {
	m.stopServer()
	for i := range m.tunnels {
		m.stopTunnel(i)
	}
}

// ─── Proxychains ──────────────────────────────────────────────────────────────

func (m model) writeProxychains() {
	content := `# Generated by chisel-orchestrator
strict_chain
quiet_mode
proxy_dns

[ProxyList]
socks5 127.0.0.1 1080
`
	err := os.WriteFile("/etc/proxychains4.conf", []byte(content), 0644)
	if err != nil {
		// try local fallback
		os.WriteFile("proxychains4.conf", []byte(content), 0644)
	}
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	p := tea.NewProgram(
		initialModel(),
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)

	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

//
//

# install deps
go mod init chisel-orchestrator
go get github.com/charmbracelet/bubbletea
go get github.com/charmbracelet/lipgloss

# set your target
export CHISEL_TARGET="10.10.10.10:8080"

# run
go run main.go

//
//
