package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type WireGuardManager struct {
	peers         map[string]*WGPeer
	config        *Config
	isWSL         bool
	windowsHostIP string
	serverPubKey  string
	nextIP        int
	mutex         sync.RWMutex
}

type WGPeer struct {
	NodeID      string    `json:"node_id"`
	Name        string    `json:"name"`
	PublicKey   string    `json:"public_key"`
	PrivateKey  string    `json:"private_key"`
	AssignedIP  string    `json:"assigned_ip"`
	Status      string    `json:"status"`
	Created     time.Time `json:"created"`
	LastSeen    time.Time `json:"last_seen"`
}

func NewWireGuardManager(config *Config) *WireGuardManager {
	wm := &WireGuardManager{
		peers:  make(map[string]*WGPeer),
		config: config,
		nextIP: 5, // Start assigning IPs from 10.66.0.5
	}

	// Detect WSL2 environment
	wm.isWSL = config.IsWSL()
	if wm.isWSL {
		wm.windowsHostIP = wm.getWindowsHostIP()
		log.Printf("Detected WSL2 environment, Windows host: %s", wm.windowsHostIP)
	}

	// Load server public key
	wm.loadServerPublicKey()

	return wm
}

func (wm *WireGuardManager) CreatePeer(nodeID, nodeName string) (*WGPeer, error) {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	// Check if peer already exists
	if _, exists := wm.peers[nodeID]; exists {
		return nil, fmt.Errorf("peer already exists for node %s", nodeID)
	}

	// Generate WireGuard keypair
	privateKey, err := wm.generatePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	publicKey, err := wm.derivePublicKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}

	// Assign IP address
	assignedIP, err := wm.allocateIP()
	if err != nil {
		return nil, fmt.Errorf("failed to allocate IP: %w", err)
	}

	peer := &WGPeer{
		NodeID:     nodeID,
		Name:       nodeName,
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		AssignedIP: assignedIP,
		Status:     "created",
		Created:    time.Now(),
	}

	// Add peer to server configuration
	if err := wm.addPeerToServer(peer); err != nil {
		return nil, fmt.Errorf("failed to add peer to server: %w", err)
	}

	wm.peers[nodeID] = peer
	log.Printf("Created WireGuard peer %s with IP %s", nodeName, assignedIP)

	return peer, nil
}

func (wm *WireGuardManager) RemovePeer(nodeID string) error {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	peer, exists := wm.peers[nodeID]
	if !exists {
		return fmt.Errorf("peer not found: %s", nodeID)
	}

	// Remove from server configuration
	if err := wm.removePeerFromServer(peer); err != nil {
		log.Printf("Warning: Failed to remove peer from server: %v", err)
	}

	delete(wm.peers, nodeID)
	log.Printf("Removed WireGuard peer %s", peer.Name)

	return nil
}

func (wm *WireGuardManager) GetPeer(nodeID string) (*WGPeer, bool) {
	wm.mutex.RLock()
	defer wm.mutex.RUnlock()
	peer, exists := wm.peers[nodeID]
	return peer, exists
}

func (wm *WireGuardManager) SetupRouting(targetNetwork, peerIP string) error {
	if wm.isWSL {
		return wm.setupRoutingWSL(targetNetwork, peerIP)
	} else {
		return wm.setupRoutingLinux(targetNetwork, peerIP)
	}
}

func (wm *WireGuardManager) CheckPeerConnectivity(nodeID string) string {
	wm.mutex.RLock()
	peer, exists := wm.peers[nodeID]
	wm.mutex.RUnlock()

	if !exists {
		return "offline"
	}

	// Ping the peer to check connectivity
	ctx := exec.Command("ping", "-c", "1", "-W", "2", peer.AssignedIP)
	if err := ctx.Run(); err != nil {
		return "offline"
	}

	peer.LastSeen = time.Now()
	return "online"
}

func (wm *WireGuardManager) GenerateClientConfig(nodeID string) (string, error) {
	peer, exists := wm.GetPeer(nodeID)
	if !exists {
		return "", fmt.Errorf("peer not found: %s", nodeID)
	}

	// Determine server endpoint
	serverEndpoint := fmt.Sprintf("your-server.com:%d", wm.config.WireGuardServerPort)
	if wm.isWSL && wm.windowsHostIP != "" {
		serverEndpoint = fmt.Sprintf("%s:%d", wm.windowsHostIP, wm.config.WireGuardServerPort)
	}

	config := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/24
DNS = 1.1.1.1

[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = %s
PersistentKeepalive = 25

# Enable packet forwarding and NAT for scanning
PostUp = iptables -A FORWARD -i %%i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; echo 1 > /proc/sys/net/ipv4/ip_forward
PostDown = iptables -D FORWARD -i %%i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
`,
		peer.PrivateKey,
		peer.AssignedIP,
		wm.serverPubKey,
		serverEndpoint,
		wm.config.WireGuardNetwork,
	)

	return config, nil
}

func (wm *WireGuardManager) Close() {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	// Clean up all peers
	for nodeID := range wm.peers {
		if peer := wm.peers[nodeID]; peer != nil {
			wm.removePeerFromServer(peer)
		}
	}

	wm.peers = make(map[string]*WGPeer)
}

// Private methods

func (wm *WireGuardManager) generatePrivateKey() (string, error) {
	// Use wg genkey command for proper WireGuard key generation
	cmd := exec.Command("wg", "genkey")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to generate private key: %w", err)
	}

	return strings.TrimSpace(string(output)), nil
}

func (wm *WireGuardManager) derivePublicKey(privateKeyStr string) (string, error) {
	// Use wg pubkey command to derive public key from private key
	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(privateKeyStr)

	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to derive public key: %w", err)
	}

	return strings.TrimSpace(string(output)), nil
}

func (wm *WireGuardManager) allocateIP() (string, error) {
	// Simple IP allocation: 10.66.0.5, 10.66.0.6, etc.
	for i := wm.nextIP; i < 255; i++ {
		ip := fmt.Sprintf("10.66.0.%d", i)

		// Check if IP is already allocated
		allocated := false
		for _, peer := range wm.peers {
			if peer.AssignedIP == ip {
				allocated = true
				break
			}
		}

		if !allocated {
			wm.nextIP = i + 1
			return ip, nil
		}
	}

	return "", fmt.Errorf("no free IP addresses available")
}

func (wm *WireGuardManager) addPeerToServer(peer *WGPeer) error {
	if wm.isWSL {
		return wm.addPeerWindows(peer)
	} else {
		return wm.addPeerLinux(peer)
	}
}

func (wm *WireGuardManager) removePeerFromServer(peer *WGPeer) error {
	if wm.isWSL {
		return wm.removePeerWindows(peer)
	} else {
		return wm.removePeerLinux(peer)
	}
}

func (wm *WireGuardManager) addPeerLinux(peer *WGPeer) error {
	// Add peer to Linux WireGuard interface
	cmd := exec.Command("wg", "set", "wg0", "peer", peer.PublicKey,
		"allowed-ips", fmt.Sprintf("%s/32", peer.AssignedIP))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add peer to Linux WireGuard: %w, output: %s", err, string(output))
	}

	return nil
}

func (wm *WireGuardManager) addPeerWindows(peer *WGPeer) error {
	// Use WSL interop to call Windows PowerShell
	psScript := fmt.Sprintf(`
		# Add peer to Windows WireGuard interface
		$interface = "wg0"
		$peerKey = "%s"
		$allowedIPs = "%s/32"

		# Try using wg.exe command
		try {
			& wg set $interface peer $peerKey allowed-ips $allowedIPs
			Write-Output "Peer added successfully"
		} catch {
			Write-Error "Failed to add peer: $_"
			exit 1
		}
	`, peer.PublicKey, peer.AssignedIP)

	cmd := exec.Command("powershell.exe", "-Command", psScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add Windows WireGuard peer: %w, output: %s", err, string(output))
	}

	return nil
}

func (wm *WireGuardManager) removePeerLinux(peer *WGPeer) error {
	cmd := exec.Command("wg", "set", "wg0", "peer", peer.PublicKey, "remove")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove peer from Linux WireGuard: %w, output: %s", err, string(output))
	}
	return nil
}

func (wm *WireGuardManager) removePeerWindows(peer *WGPeer) error {
	psScript := fmt.Sprintf(`
		$interface = "wg0"
		$peerKey = "%s"

		try {
			& wg set $interface peer $peerKey remove
			Write-Output "Peer removed successfully"
		} catch {
			Write-Error "Failed to remove peer: $_"
			exit 1
		}
	`, peer.PublicKey)

	cmd := exec.Command("powershell.exe", "-Command", psScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove Windows WireGuard peer: %w, output: %s", err, string(output))
	}

	return nil
}

func (wm *WireGuardManager) setupRoutingLinux(targetNetwork, peerIP string) error {
	// Add route through WireGuard interface
	cmd := exec.Command("ip", "route", "add", targetNetwork, "via", peerIP, "dev", "wg0")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add route via WireGuard: %w", err)
	}

	log.Printf("Added route: %s via %s dev wg0", targetNetwork, peerIP)
	return nil
}

func (wm *WireGuardManager) setupRoutingWSL(targetNetwork, peerIP string) error {
	// For WSL2, we need to route through the Windows WireGuard interface
	// This is more complex and may require additional setup

	log.Printf("Setting up WSL2 routing for %s via %s", targetNetwork, peerIP)

	// Add route via default gateway first (Windows will handle WireGuard routing)
	cmd := exec.Command("ip", "route", "add", targetNetwork, "via", wm.windowsHostIP)
	if err := cmd.Run(); err != nil {
		// If that fails, try direct routing
		cmd = exec.Command("ip", "route", "add", targetNetwork, "via", peerIP)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to add WSL2 route: %w", err)
		}
	}

	return nil
}

func (wm *WireGuardManager) getWindowsHostIP() string {
	// Get the default route gateway (Windows host IP from WSL2 perspective)
	cmd := exec.Command("ip", "route", "show", "default")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("Warning: Could not determine Windows host IP: %v", err)
		return ""
	}

	// Parse "default via 172.x.x.1 dev eth0"
	parts := strings.Fields(string(output))
	for i, part := range parts {
		if part == "via" && i+1 < len(parts) {
			ip := strings.TrimSpace(parts[i+1])
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}

	return ""
}

func (wm *WireGuardManager) loadServerPublicKey() {
	// Try to load server public key from various locations
	locations := []string{
		"/etc/tunnel-manager/wireguard/server_public_key",
		"/etc/wireguard/server_public_key",
		filepath.Join(wm.config.WireGuardConfig, "server_public_key"),
	}

	for _, location := range locations {
		if content, err := os.ReadFile(location); err == nil {
			wm.serverPubKey = strings.TrimSpace(string(content))
			log.Printf("Loaded WireGuard server public key from %s", location)
			return
		}
	}

	// Generate a placeholder key for development
	log.Printf("Warning: No WireGuard server public key found, using placeholder")
	wm.serverPubKey = "PLACEHOLDER_SERVER_PUBLIC_KEY_UPDATE_IN_CONFIG"
}