package main

import (
	"database/sql"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

type PortAllocator struct {
	allocated   map[int]*PortAllocation // port -> allocation info
	startPort   int
	endPort     int
	db          *sql.DB
	mutex       sync.RWMutex
}

type PortAllocation struct {
	Port       int       `json:"port"`
	NodeID     string    `json:"node_id"`
	TunnelType string    `json:"tunnel_type"` // "ssh" or "wireguard"
	Allocated  time.Time `json:"allocated"`
}

func NewPortAllocator(db *sql.DB, startPort, endPort int) *PortAllocator {
	return &PortAllocator{
		allocated: make(map[int]*PortAllocation),
		startPort: startPort,
		endPort:   endPort,
		db:        db,
	}
}

func (pa *PortAllocator) LoadFromDB() error {
	pa.mutex.Lock()
	defer pa.mutex.Unlock()

	// Load existing port allocations from database
	rows, err := pa.db.Query(`
		SELECT id, proxy_port, 'ssh' as tunnel_type, created_at
		FROM remote_nodes
		WHERE node_type = 'ssh' AND proxy_port IS NOT NULL AND status != 'error'
		UNION ALL
		SELECT id, wg_port_assigned as proxy_port, 'wireguard' as tunnel_type, created_at
		FROM remote_nodes
		WHERE node_type = 'ssh' AND wg_port_assigned IS NOT NULL AND tunnel_method IN ('wireguard', 'hybrid')
	`)
	if err != nil {
		return fmt.Errorf("failed to query port allocations: %w", err)
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var nodeID, tunnelType string
		var port int
		var allocated time.Time

		if err := rows.Scan(&nodeID, &port, &tunnelType, &allocated); err != nil {
			log.Printf("Warning: Failed to scan port allocation: %v", err)
			continue
		}

		// Only reserve ports in our range
		if port >= pa.startPort && port <= pa.endPort {
			pa.allocated[port] = &PortAllocation{
				Port:       port,
				NodeID:     nodeID,
				TunnelType: tunnelType,
				Allocated:  allocated,
			}
			count++
		}
	}

	log.Printf("Loaded %d port allocations from database", count)
	return nil
}

func (pa *PortAllocator) AllocateSSH(nodeID string) int {
	return pa.allocatePort(nodeID, "ssh")
}

func (pa *PortAllocator) AllocateWireGuard(nodeID string) int {
	return pa.allocatePort(nodeID, "wireguard")
}

func (pa *PortAllocator) allocatePort(nodeID, tunnelType string) int {
	pa.mutex.Lock()
	defer pa.mutex.Unlock()

	// Find first available port
	for port := pa.startPort; port <= pa.endPort; port++ {
		if pa.isPortAvailableUnsafe(port) {
			allocation := &PortAllocation{
				Port:       port,
				NodeID:     nodeID,
				TunnelType: tunnelType,
				Allocated:  time.Now(),
			}
			pa.allocated[port] = allocation
			log.Printf("Allocated port %d for %s tunnel (node: %s)", port, tunnelType, nodeID)
			return port
		}
	}

	log.Printf("Warning: No available ports in range %d-%d", pa.startPort, pa.endPort)
	return 0
}

func (pa *PortAllocator) ReleasePort(port int) {
	pa.mutex.Lock()
	defer pa.mutex.Unlock()

	if allocation, exists := pa.allocated[port]; exists {
		log.Printf("Released port %d (was %s tunnel for node %s)", port, allocation.TunnelType, allocation.NodeID)
		delete(pa.allocated, port)
	}
}

func (pa *PortAllocator) ReservePort(port int, nodeID, tunnelType string) bool {
	pa.mutex.Lock()
	defer pa.mutex.Unlock()

	if pa.isPortAvailableUnsafe(port) {
		allocation := &PortAllocation{
			Port:       port,
			NodeID:     nodeID,
			TunnelType: tunnelType,
			Allocated:  time.Now(),
		}
		pa.allocated[port] = allocation
		log.Printf("Reserved port %d for %s tunnel (node: %s)", port, tunnelType, nodeID)
		return true
	}

	return false
}

func (pa *PortAllocator) IsPortFree(port int) bool {
	pa.mutex.RLock()
	defer pa.mutex.RUnlock()
	return pa.isPortAvailableUnsafe(port)
}

func (pa *PortAllocator) GetNodePorts(nodeID string) []PortAllocation {
	pa.mutex.RLock()
	defer pa.mutex.RUnlock()

	var ports []PortAllocation
	for _, allocation := range pa.allocated {
		if allocation.NodeID == nodeID {
			ports = append(ports, *allocation)
		}
	}

	return ports
}

func (pa *PortAllocator) GetPortInfo(port int) *PortAllocation {
	pa.mutex.RLock()
	defer pa.mutex.RUnlock()

	if allocation, exists := pa.allocated[port]; exists {
		return allocation
	}
	return nil
}

func (pa *PortAllocator) GetAllAllocations() map[int]*PortAllocation {
	pa.mutex.RLock()
	defer pa.mutex.RUnlock()

	// Return a copy to avoid race conditions
	result := make(map[int]*PortAllocation)
	for k, v := range pa.allocated {
		result[k] = &PortAllocation{
			Port:       v.Port,
			NodeID:     v.NodeID,
			TunnelType: v.TunnelType,
			Allocated:  v.Allocated,
		}
	}
	return result
}

func (pa *PortAllocator) EnsurePortFree(port int, nodeID string) int {
	pa.mutex.Lock()
	defer pa.mutex.Unlock()

	// If port is available, reserve it
	if pa.isPortAvailableUnsafe(port) {
		allocation := &PortAllocation{
			Port:       port,
			NodeID:     nodeID,
			TunnelType: "ssh", // Default to SSH
			Allocated:  time.Now(),
		}
		pa.allocated[port] = allocation
		return port
	}

	// Port is occupied, find a new one
	for newPort := pa.startPort; newPort <= pa.endPort; newPort++ {
		if pa.isPortAvailableUnsafe(newPort) {
			allocation := &PortAllocation{
				Port:       newPort,
				NodeID:     nodeID,
				TunnelType: "ssh",
				Allocated:  time.Now(),
			}
			pa.allocated[newPort] = allocation
			log.Printf("Port %d was occupied, reassigned to %d for node %s", port, newPort, nodeID)
			return newPort
		}
	}

	log.Printf("Warning: Could not reassign port %d for node %s, no ports available", port, nodeID)
	return 0
}

// Private methods

func (pa *PortAllocator) isPortAvailableUnsafe(port int) bool {
	// Check if port is in our allocation map
	if _, allocated := pa.allocated[port]; allocated {
		return false
	}

	// Check if port is actually free at OS level
	return pa.isPortFreeOS(port)
}

func (pa *PortAllocator) isPortFreeOS(port int) bool {
	// Try to bind to the port to see if it's free
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

func (pa *PortAllocator) cleanupOrphanedPorts() {
	pa.mutex.Lock()
	defer pa.mutex.Unlock()

	cleaned := 0
	for port, allocation := range pa.allocated {
		// Check if port is actually in use
		if pa.isPortFreeOS(port) {
			log.Printf("Found orphaned port allocation: %d (node: %s), cleaning up", port, allocation.NodeID)
			delete(pa.allocated, port)
			cleaned++
		}
	}

	if cleaned > 0 {
		log.Printf("Cleaned up %d orphaned port allocations", cleaned)
	}
}

// Utility functions for port range validation
func (pa *PortAllocator) IsInRange(port int) bool {
	return port >= pa.startPort && port <= pa.endPort
}

func (pa *PortAllocator) GetRange() (int, int) {
	return pa.startPort, pa.endPort
}

func (pa *PortAllocator) GetStats() map[string]interface{} {
	pa.mutex.RLock()
	defer pa.mutex.RUnlock()

	totalPorts := pa.endPort - pa.startPort + 1
	allocatedPorts := len(pa.allocated)

	sshPorts := 0
	wgPorts := 0
	for _, allocation := range pa.allocated {
		if allocation.TunnelType == "ssh" {
			sshPorts++
		} else if allocation.TunnelType == "wireguard" {
			wgPorts++
		}
	}

	return map[string]interface{}{
		"total_ports":     totalPorts,
		"allocated_ports": allocatedPorts,
		"free_ports":      totalPorts - allocatedPorts,
		"ssh_ports":       sshPorts,
		"wireguard_ports": wgPorts,
		"range_start":     pa.startPort,
		"range_end":       pa.endPort,
	}
}