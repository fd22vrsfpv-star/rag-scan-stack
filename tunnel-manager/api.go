package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// API Request/Response structures
type SSHConnectRequest struct {
	Host        string `json:"host" binding:"required"`
	User        string `json:"user" binding:"required"`
	SSHPort     int    `json:"ssh_port"`
	KeyName     string `json:"key_name" binding:"required"`
	Name        string `json:"name"`
	OSType      string `json:"os_type"`
	Provider    string `json:"provider"`
}

type WireGuardCreateRequest struct {
	NodeID   string `json:"node_id" binding:"required"`
	NodeName string `json:"node_name" binding:"required"`
}

type RoutingSetupRequest struct {
	TargetNetwork string `json:"target_network" binding:"required"`
	PeerIP        string `json:"peer_ip" binding:"required"`
}

type TunnelStatusResponse struct {
	NodeID  string                 `json:"node_id"`
	Tunnels map[string]interface{} `json:"tunnels"`
}

type CommandExecRequest struct {
	Command string `json:"command" binding:"required"`
	Timeout int    `json:"timeout,omitempty"`
}

func setupRoutes(tm *TunnelManager) *gin.Engine {
	r := gin.Default()

	// Add request logging middleware
	r.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf("%s - [%s] \"%s %s %s %d %s \"%s\" %s\"\n",
			param.ClientIP,
			param.TimeStamp.Format(time.RFC1123),
			param.Method,
			param.Path,
			param.Request.Proto,
			param.StatusCode,
			param.Latency,
			param.Request.UserAgent(),
			param.ErrorMessage,
		)
	}))

	// Recovery middleware
	r.Use(gin.Recovery())

	// Health check
	r.GET("/health", func(c *gin.Context) {
		stats := tm.portAlloc.GetStats()
		c.JSON(http.StatusOK, gin.H{
			"status":      "healthy",
			"version":     "1.0.0",
			"port_stats":  stats,
			"tunnel_count": len(tm.sshManager.GetAllTunnels()),
			"wg_peers":    len(tm.wgManager.peers),
		})
	})

	// SSH tunnel management
	ssh := r.Group("/ssh")
	{
		ssh.POST("/connect", tm.connectSSH)
		ssh.POST("/:node_id/disconnect", tm.disconnectSSH)
		ssh.POST("/:node_id/reconnect", tm.reconnectSSH)
		ssh.GET("/:node_id/status", tm.getSSHStatus)
		ssh.POST("/:node_id/exec", tm.execSSHCommand)
	}

	// WireGuard management
	wg := r.Group("/wireguard")
	{
		wg.POST("/create-peer", tm.createWGPeer)
		wg.POST("/:node_id/setup-routing", tm.setupWGRouting)
		wg.GET("/:node_id/config", tm.getWGClientConfig)
		wg.GET("/:node_id/status", tm.getWGStatus)
		wg.DELETE("/:node_id", tm.removeWGPeer)
	}

	// Unified tunnel management
	tunnel := r.Group("/tunnel")
	{
		tunnel.GET("/:node_id/status", tm.getTunnelStatus)
		tunnel.GET("/:node_id/ports", tm.getTunnelPorts)
		tunnel.POST("/:node_id/migrate", tm.migrateTunnelType)
	}

	// Port management
	ports := r.Group("/ports")
	{
		ports.GET("/stats", tm.getPortStats)
		ports.GET("/allocations", tm.getPortAllocations)
		ports.POST("/:port/release", tm.releasePort)
	}

	return r
}

// SSH Tunnel Endpoints

func (tm *TunnelManager) connectSSH(c *gin.Context) {
	var req SSHConnectRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Set defaults
	if req.SSHPort == 0 {
		req.SSHPort = 22
	}
	if req.Name == "" {
		req.Name = fmt.Sprintf("%s@%s", req.User, req.Host)
	}

	// Allocate port
	port := tm.portAlloc.AllocateSSH("temp") // Temporary allocation
	if port == 0 {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "No available ports"})
		return
	}

	// Create tunnel
	nodeID := generateNodeID()
	tunnel := &SSHTunnel{
		NodeID:    nodeID,
		Name:      req.Name,
		Host:      req.Host,
		User:      req.User,
		SSHPort:   req.SSHPort,
		KeyFile:   req.KeyName,
		SOCKSPort: port,
	}

	// Start tunnel
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := tm.sshManager.StartTunnel(ctx, tunnel); err != nil {
		tm.portAlloc.ReleasePort(port)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to start tunnel: %v", err)})
		return
	}

	// Update port allocation with real node ID
	tm.portAlloc.ReleasePort(port)
	if !tm.portAlloc.ReservePort(port, nodeID, "ssh") {
		log.Printf("Warning: Could not re-reserve port %d for node %s", port, nodeID)
	}

	// Save to database
	metadata := map[string]interface{}{
		"host":     req.Host,
		"user":     req.User,
		"ssh_port": req.SSHPort,
		"key_file": req.KeyName,
		"os_type":  req.OSType,
		"provider": req.Provider,
	}

	if err := tm.saveNodeToDB(nodeID, req.Name, "ssh", "online", port, 0, metadata); err != nil {
		log.Printf("Warning: Failed to save node to database: %v", err)
	}

	c.JSON(http.StatusOK, gin.H{
		"id":          nodeID,
		"name":        req.Name,
		"proxy_port":  port,
		"status":      "online",
		"tunnel_type": "ssh",
	})
}

func (tm *TunnelManager) disconnectSSH(c *gin.Context) {
	nodeID := c.Param("node_id")

	if err := tm.sshManager.StopTunnel(nodeID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	// Update database
	_, err := tm.db.Exec("UPDATE remote_nodes SET status = 'offline', ssh_health = 'offline' WHERE id = $1", nodeID)
	if err != nil {
		log.Printf("Warning: Failed to update node status: %v", err)
	}

	c.JSON(http.StatusOK, gin.H{"status": "disconnected"})
}

func (tm *TunnelManager) reconnectSSH(c *gin.Context) {
	nodeID := c.Param("node_id")

	// Get tunnel info from database
	var name, host, user, keyFile string
	var sshPort, proxyPort int

	err := tm.db.QueryRow(`
		SELECT name, metadata->'host', metadata->'user', metadata->'key_file',
		       COALESCE((metadata->'ssh_port')::text, '22')::int, proxy_port
		FROM remote_nodes WHERE id = $1 AND node_type = 'ssh'`,
		nodeID).Scan(&name, &host, &user, &keyFile, &sshPort, &proxyPort)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Node not found"})
		return
	}

	// Ensure port is available
	newPort := tm.portAlloc.EnsurePortFree(proxyPort, nodeID)
	if newPort == 0 {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "No available ports"})
		return
	}

	// Update database if port changed
	if newPort != proxyPort {
		_, err := tm.db.Exec("UPDATE remote_nodes SET proxy_port = $1 WHERE id = $2", newPort, nodeID)
		if err != nil {
			log.Printf("Warning: Failed to update port: %v", err)
		}
		proxyPort = newPort
	}

	// Create and start tunnel
	tunnel := &SSHTunnel{
		NodeID:    nodeID,
		Name:      name,
		Host:      host,
		User:      user,
		SSHPort:   sshPort,
		KeyFile:   keyFile,
		SOCKSPort: proxyPort,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := tm.sshManager.StartTunnel(ctx, tunnel); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to reconnect: %v", err)})
		return
	}

	// Update database
	_, err = tm.db.Exec("UPDATE remote_nodes SET status = 'online', ssh_health = 'online' WHERE id = $1", nodeID)
	if err != nil {
		log.Printf("Warning: Failed to update node status: %v", err)
	}

	c.JSON(http.StatusOK, gin.H{
		"status":     "reconnected",
		"proxy_port": proxyPort,
	})
}

func (tm *TunnelManager) getSSHStatus(c *gin.Context) {
	nodeID := c.Param("node_id")

	tunnel, exists := tm.sshManager.GetTunnel(nodeID)
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Tunnel not found"})
		return
	}

	status := tm.sshManager.CheckTunnelHealth(nodeID)

	c.JSON(http.StatusOK, gin.H{
		"node_id":     nodeID,
		"name":        tunnel.Name,
		"status":      status,
		"proxy_port":  tunnel.SOCKSPort,
		"host":        tunnel.Host,
		"started":     tunnel.Started,
		"tunnel_type": "ssh",
	})
}

func (tm *TunnelManager) execSSHCommand(c *gin.Context) {
	nodeID := c.Param("node_id")

	var req CommandExecRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	output, err := tm.sshManager.ExecuteCommand(nodeID, req.Command)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":  err.Error(),
			"output": output,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"output":     output,
		"exit_code":  0,
		"command":    req.Command,
	})
}

// WireGuard Endpoints

func (tm *TunnelManager) createWGPeer(c *gin.Context) {
	var req WireGuardCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	peer, err := tm.wgManager.CreatePeer(req.NodeID, req.NodeName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Update database
	_, err = tm.db.Exec(`
		UPDATE remote_nodes
		SET wg_public_key = $1, wg_assigned_ip = $2, tunnel_method = 'hybrid'
		WHERE id = $3`,
		peer.PublicKey, peer.AssignedIP, req.NodeID)
	if err != nil {
		log.Printf("Warning: Failed to update WireGuard info in database: %v", err)
	}

	c.JSON(http.StatusOK, gin.H{
		"node_id":     peer.NodeID,
		"public_key":  peer.PublicKey,
		"assigned_ip": peer.AssignedIP,
		"status":      peer.Status,
	})
}

func (tm *TunnelManager) setupWGRouting(c *gin.Context) {
	var req RoutingSetupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := tm.wgManager.SetupRouting(req.TargetNetwork, req.PeerIP); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":         "routing_configured",
		"target_network": req.TargetNetwork,
		"peer_ip":        req.PeerIP,
	})
}

func (tm *TunnelManager) getWGClientConfig(c *gin.Context) {
	nodeID := c.Param("node_id")

	config, err := tm.wgManager.GenerateClientConfig(nodeID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.Header("Content-Type", "text/plain")
	c.String(http.StatusOK, config)
}

func (tm *TunnelManager) getWGStatus(c *gin.Context) {
	nodeID := c.Param("node_id")

	peer, exists := tm.wgManager.GetPeer(nodeID)
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "WireGuard peer not found"})
		return
	}

	status := tm.wgManager.CheckPeerConnectivity(nodeID)

	c.JSON(http.StatusOK, gin.H{
		"node_id":     nodeID,
		"status":      status,
		"assigned_ip": peer.AssignedIP,
		"public_key":  peer.PublicKey,
		"last_seen":   peer.LastSeen,
		"tunnel_type": "wireguard",
	})
}

func (tm *TunnelManager) removeWGPeer(c *gin.Context) {
	nodeID := c.Param("node_id")

	if err := tm.wgManager.RemovePeer(nodeID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	// Update database
	_, err := tm.db.Exec(`
		UPDATE remote_nodes
		SET wg_public_key = NULL, wg_assigned_ip = NULL, tunnel_method = 'ssh'
		WHERE id = $1`,
		nodeID)
	if err != nil {
		log.Printf("Warning: Failed to update database: %v", err)
	}

	c.JSON(http.StatusOK, gin.H{"status": "peer_removed"})
}

// Unified Tunnel Endpoints

func (tm *TunnelManager) getTunnelStatus(c *gin.Context) {
	nodeID := c.Param("node_id")

	response := TunnelStatusResponse{
		NodeID:  nodeID,
		Tunnels: make(map[string]interface{}),
	}

	// Check SSH tunnel
	if tunnel, exists := tm.sshManager.GetTunnel(nodeID); exists {
		sshStatus := tm.sshManager.CheckTunnelHealth(nodeID)
		response.Tunnels["ssh"] = gin.H{
			"status": sshStatus,
			"port":   tunnel.SOCKSPort,
			"host":   tunnel.Host,
		}
	} else {
		response.Tunnels["ssh"] = gin.H{
			"status": "offline",
			"port":   nil,
		}
	}

	// Check WireGuard peer
	if peer, exists := tm.wgManager.GetPeer(nodeID); exists {
		wgStatus := tm.wgManager.CheckPeerConnectivity(nodeID)
		response.Tunnels["wireguard"] = gin.H{
			"status":      wgStatus,
			"assigned_ip": peer.AssignedIP,
		}
	} else {
		response.Tunnels["wireguard"] = gin.H{
			"status":      "offline",
			"assigned_ip": nil,
		}
	}

	c.JSON(http.StatusOK, response)
}

func (tm *TunnelManager) getTunnelPorts(c *gin.Context) {
	nodeID := c.Param("node_id")

	ports := tm.portAlloc.GetNodePorts(nodeID)

	c.JSON(http.StatusOK, gin.H{
		"node_id": nodeID,
		"ports":   ports,
	})
}

func (tm *TunnelManager) migrateTunnelType(c *gin.Context) {
	// TODO: Implement tunnel type migration (SSH -> WireGuard, etc.)
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Migration not yet implemented"})
}

// Port Management Endpoints

func (tm *TunnelManager) getPortStats(c *gin.Context) {
	stats := tm.portAlloc.GetStats()
	c.JSON(http.StatusOK, stats)
}

func (tm *TunnelManager) getPortAllocations(c *gin.Context) {
	allocations := tm.portAlloc.GetAllAllocations()
	c.JSON(http.StatusOK, gin.H{
		"allocations": allocations,
	})
}

func (tm *TunnelManager) releasePort(c *gin.Context) {
	portStr := c.Param("port")
	port, err := strconv.Atoi(portStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid port number"})
		return
	}

	tm.portAlloc.ReleasePort(port)
	c.JSON(http.StatusOK, gin.H{"status": "port_released", "port": port})
}

// Helper functions

func generateNodeID() string {
	// Simple UUID generation for demo
	return fmt.Sprintf("node-%d", time.Now().UnixNano())
}

func (tm *TunnelManager) saveNodeToDB(nodeID, name, nodeType, status string, sshPort, wgPort int, metadata map[string]interface{}) error {
	query := `
		INSERT INTO remote_nodes (id, name, node_type, status, proxy_port, ssh_port_assigned, wg_port_assigned, metadata, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now(), now())
		ON CONFLICT (id) DO UPDATE SET
			status = $4, proxy_port = $5, ssh_port_assigned = $6, wg_port_assigned = $7, metadata = $8, updated_at = now()
	`

	var metadataJSON []byte
	if metadata != nil {
		var err error
		metadataJSON, err = json.Marshal(metadata)
		if err != nil {
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}
	}

	_, err := tm.db.Exec(query, nodeID, name, nodeType, status, sshPort, sshPort, wgPort, metadataJSON)
	return err
}