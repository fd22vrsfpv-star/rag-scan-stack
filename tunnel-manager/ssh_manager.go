package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

type SSHManager struct {
	tunnels   map[string]*SSHTunnel
	portAlloc *PortAllocator
	keysDir   string
	mutex     sync.RWMutex
}

type SSHTunnel struct {
	NodeID    string    `json:"node_id"`
	Name      string    `json:"name"`
	Host      string    `json:"host"`
	User      string    `json:"user"`
	SSHPort   int       `json:"ssh_port"`
	KeyFile   string    `json:"key_file"`
	SOCKSPort int       `json:"socks_port"`
	Status    string    `json:"status"`
	Process   *exec.Cmd `json:"-"`
	Started   time.Time `json:"started"`
}

func NewSSHManager(keysDir string, portAlloc *PortAllocator) *SSHManager {
	return &SSHManager{
		tunnels:   make(map[string]*SSHTunnel),
		portAlloc: portAlloc,
		keysDir:   keysDir,
	}
}

func (sm *SSHManager) StartTunnel(ctx context.Context, tunnel *SSHTunnel) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// Kill any existing process on this port
	if err := sm.killPortProcesses(tunnel.SOCKSPort); err != nil {
		log.Printf("Warning: Failed to kill processes on port %d: %v", tunnel.SOCKSPort, err)
	}

	// Verify SSH key exists
	keyPath := filepath.Join(sm.keysDir, tunnel.KeyFile)
	if !fileExists(keyPath) {
		return fmt.Errorf("SSH key file not found: %s", keyPath)
	}

	// Set up control socket path
	controlPath := fmt.Sprintf("/tmp/ssh-control-%s", tunnel.NodeID)

	// Build autossh command
	cmd := exec.CommandContext(ctx, "autossh",
		"-M", "0", // Disable autossh monitoring port
		"-N",      // Don't execute remote command
		"-T",      // Disable TTY allocation
		"-D", fmt.Sprintf("0.0.0.0:%d", tunnel.SOCKSPort), // SOCKS proxy
		"-i", keyPath,                                      // SSH key
		"-p", strconv.Itoa(tunnel.SSHPort),                 // SSH port
		"-o", fmt.Sprintf("ControlPath=%s", controlPath),   // Control socket
		"-o", "ControlMaster=auto",                         // SSH multiplexing
		"-o", "StrictHostKeyChecking=no",                   // Skip host key checking
		"-o", "UserKnownHostsFile=/dev/null",              // Don't save host keys
		"-o", "ServerAliveInterval=15",                     // Heartbeat every 15s
		"-o", "ServerAliveCountMax=5",                      // Max 5 missed heartbeats (75s total)
		"-o", "ConnectTimeout=15",                          // 15s connection timeout
		"-o", "ConnectionAttempts=3",                       // Retry 3 times
		"-o", "ExitOnForwardFailure=yes",                   // Exit if SOCKS binding fails
		fmt.Sprintf("%s@%s", tunnel.User, tunnel.Host),
	)

	// Set up process attributes
	cmd.Stdout = nil
	cmd.Stderr = nil

	// Start the process
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start autossh process: %w", err)
	}

	tunnel.Process = cmd
	tunnel.Status = "connecting"
	tunnel.Started = time.Now()

	// Store tunnel
	sm.tunnels[tunnel.NodeID] = tunnel

	// Wait for SOCKS port to become available (with timeout)
	if err := sm.waitForSOCKSPort(tunnel.SOCKSPort, 30*time.Second); err != nil {
		// Kill the process if SOCKS port doesn't come up
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		delete(sm.tunnels, tunnel.NodeID)
		return fmt.Errorf("SOCKS port %d never became available: %w", tunnel.SOCKSPort, err)
	}

	tunnel.Status = "online"
	log.Printf("SSH tunnel %s started successfully on port %d", tunnel.Name, tunnel.SOCKSPort)

	return nil
}

func (sm *SSHManager) StopTunnel(nodeID string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	tunnel, exists := sm.tunnels[nodeID]
	if !exists {
		return fmt.Errorf("tunnel not found: %s", nodeID)
	}

	// Kill the process
	if tunnel.Process != nil && tunnel.Process.Process != nil {
		if err := tunnel.Process.Process.Kill(); err != nil {
			log.Printf("Warning: Failed to kill tunnel process: %v", err)
		}
	}

	// Clean up control socket
	controlPath := fmt.Sprintf("/tmp/ssh-control-%s", nodeID)
	os.Remove(controlPath)

	// Release port
	sm.portAlloc.ReleasePort(tunnel.SOCKSPort)

	// Remove from active tunnels
	delete(sm.tunnels, nodeID)

	log.Printf("SSH tunnel %s stopped", tunnel.Name)
	return nil
}

func (sm *SSHManager) CheckTunnelHealth(nodeID string) string {
	sm.mutex.RLock()
	tunnel, exists := sm.tunnels[nodeID]
	sm.mutex.RUnlock()

	if !exists {
		return "offline"
	}

	// Check if process is still running
	if tunnel.Process == nil || tunnel.Process.ProcessState != nil {
		return "offline"
	}

	// Test SOCKS5 connectivity
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", tunnel.SOCKSPort), 2*time.Second)
	if err != nil {
		return "degraded"
	}
	defer conn.Close()

	// Send SOCKS5 greeting
	_, err = conn.Write([]byte{0x05, 0x01, 0x00}) // VER=5, NMETHODS=1, METHOD=0 (no auth)
	if err != nil {
		return "degraded"
	}

	// Read response
	response := make([]byte, 2)
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, err := conn.Read(response)
	if err != nil || n != 2 || response[0] != 0x05 {
		return "degraded"
	}

	return "online"
}

func (sm *SSHManager) GetTunnel(nodeID string) (*SSHTunnel, bool) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	tunnel, exists := sm.tunnels[nodeID]
	return tunnel, exists
}

func (sm *SSHManager) GetAllTunnels() map[string]*SSHTunnel {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	// Return a copy to avoid race conditions
	result := make(map[string]*SSHTunnel)
	for k, v := range sm.tunnels {
		result[k] = v
	}
	return result
}

func (sm *SSHManager) ExecuteCommand(nodeID, command string) (string, error) {
	sm.mutex.RLock()
	tunnel, exists := sm.tunnels[nodeID]
	sm.mutex.RUnlock()

	if !exists {
		return "", fmt.Errorf("tunnel not found: %s", nodeID)
	}

	// Use the existing control socket for command execution
	keyPath := filepath.Join(sm.keysDir, tunnel.KeyFile)
	controlPath := fmt.Sprintf("/tmp/ssh-control-%s", nodeID)

	cmd := exec.Command("ssh",
		"-i", keyPath,
		"-p", strconv.Itoa(tunnel.SSHPort),
		"-o", fmt.Sprintf("ControlPath=%s", controlPath),
		"-o", "ControlMaster=no", // Use existing master
		"-o", "StrictHostKeyChecking=no",
		fmt.Sprintf("%s@%s", tunnel.User, tunnel.Host),
		command,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("command execution failed: %w", err)
	}

	return string(output), nil
}

func (sm *SSHManager) Close() {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	for nodeID, tunnel := range sm.tunnels {
		if tunnel.Process != nil && tunnel.Process.Process != nil {
			tunnel.Process.Process.Kill()
		}
		// Clean up control socket
		controlPath := fmt.Sprintf("/tmp/ssh-control-%s", nodeID)
		os.Remove(controlPath)
	}

	sm.tunnels = make(map[string]*SSHTunnel)
}

func (sm *SSHManager) waitForSOCKSPort(port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 1*time.Second)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(1 * time.Second)
	}

	return fmt.Errorf("timeout waiting for SOCKS port %d", port)
}

func (sm *SSHManager) killPortProcesses(port int) error {
	// Find processes using the port
	cmd := exec.Command("lsof", "-ti", fmt.Sprintf(":%d", port))
	output, err := cmd.Output()
	if err != nil {
		// No processes found or lsof failed
		return nil
	}

	// Kill each process
	pids := string(output)
	if pids != "" {
		for _, pidStr := range []string{pids} {
			if pidStr != "" {
				killCmd := exec.Command("kill", "-9", pidStr)
				killCmd.Run() // Ignore errors
			}
		}
	}

	return nil
}