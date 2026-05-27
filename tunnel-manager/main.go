package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
)

type TunnelManager struct {
	db         *sql.DB
	config     *Config
	sshManager *SSHManager
	wgManager  *WireGuardManager
	portAlloc  *PortAllocator
}

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "/etc/tunnel-manager/config.yaml", "Path to configuration file")
	flag.Parse()

	// Load configuration
	config, err := LoadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Set up logging
	if config.LogLevel == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// Initialize tunnel manager
	tm, err := NewTunnelManager(config)
	if err != nil {
		log.Fatalf("Failed to create tunnel manager: %v", err)
	}
	defer tm.Close()

	// Set up HTTP router
	router := setupRoutes(tm)

	server := &http.Server{
		Addr:    config.ListenAddr,
		Handler: router,
		ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout: 120 * time.Second,
	}

	// Start health monitoring in background
	go tm.startHealthWatchdog()

	// Start server in background
	go func() {
		log.Printf("Starting tunnel manager API on %s", config.ListenAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down tunnel manager...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	log.Println("Tunnel manager stopped")
}

func NewTunnelManager(config *Config) (*TunnelManager, error) {
	// Connect to database
	db, err := sql.Open("postgres", config.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Test database connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Initialize port allocator
	portAlloc := NewPortAllocator(db, config.SSHPortStart, config.SSHPortEnd)
	if err := portAlloc.LoadFromDB(); err != nil {
		log.Printf("Warning: Failed to load port allocations from DB: %v", err)
	}

	// Initialize SSH manager
	sshManager := NewSSHManager(config.SSHKeysDir, portAlloc)

	// Initialize WireGuard manager
	wgManager := NewWireGuardManager(config)

	tm := &TunnelManager{
		db:         db,
		config:     config,
		sshManager: sshManager,
		wgManager:  wgManager,
		portAlloc:  portAlloc,
	}

	// Reload existing tunnels from database
	if err := tm.reloadExistingTunnels(); err != nil {
		log.Printf("Warning: Failed to reload existing tunnels: %v", err)
	}

	return tm, nil
}

func (tm *TunnelManager) Close() {
	if tm.db != nil {
		tm.db.Close()
	}
	if tm.sshManager != nil {
		tm.sshManager.Close()
	}
	if tm.wgManager != nil {
		tm.wgManager.Close()
	}
}

func (tm *TunnelManager) reloadExistingTunnels() error {
	// Query for existing SSH tunnels
	rows, err := tm.db.Query(`
		SELECT id, name, metadata->'host' as host, metadata->'user' as user,
		       metadata->'ssh_port' as ssh_port, metadata->'key_file' as key_file,
		       proxy_port
		FROM remote_nodes
		WHERE node_type = 'ssh' AND status = 'online' AND proxy_port IS NOT NULL
	`)
	if err != nil {
		return fmt.Errorf("failed to query existing tunnels: %w", err)
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var nodeID, name, host, user, keyFile string
		var sshPort, proxyPort int

		if err := rows.Scan(&nodeID, &name, &host, &user, &sshPort, &keyFile, &proxyPort); err != nil {
			log.Printf("Warning: Failed to scan tunnel row: %v", err)
			continue
		}

		// Ensure port is still available
		if !tm.portAlloc.IsPortFree(proxyPort) {
			log.Printf("Port %d for tunnel %s is no longer available, will reassign", proxyPort, name)
			newPort := tm.portAlloc.AllocateSSH(nodeID)
			if newPort == 0 {
				log.Printf("Warning: No free ports available for tunnel %s", name)
				continue
			}
			proxyPort = newPort

			// Update database with new port
			_, err := tm.db.Exec("UPDATE remote_nodes SET proxy_port = $1 WHERE id = $2", proxyPort, nodeID)
			if err != nil {
				log.Printf("Warning: Failed to update port for tunnel %s: %v", name, err)
			}
		} else {
			// Reserve the existing port
			tm.portAlloc.ReservePort(proxyPort, nodeID, "ssh")
		}

		// Create tunnel object
		tunnel := &SSHTunnel{
			NodeID:    nodeID,
			Name:      name,
			Host:      host,
			User:      user,
			SSHPort:   sshPort,
			KeyFile:   keyFile,
			SOCKSPort: proxyPort,
			Status:    "connecting",
		}

		// Try to reconnect
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := tm.sshManager.StartTunnel(ctx, tunnel); err != nil {
			log.Printf("Warning: Failed to reconnect tunnel %s: %v", name, err)
			// Mark as offline in database
			tm.db.Exec("UPDATE remote_nodes SET status = 'error' WHERE id = $1", nodeID)
		} else {
			log.Printf("Successfully reconnected tunnel %s on port %d", name, proxyPort)
			count++
		}
		cancel()
	}

	log.Printf("Reloaded %d existing SSH tunnels", count)
	return nil
}

func (tm *TunnelManager) startHealthWatchdog() {
	ticker := time.NewTicker(time.Duration(tm.config.HealthCheckInterval) * time.Second)
	defer ticker.Stop()

	log.Printf("Starting health watchdog (interval: %ds)", tm.config.HealthCheckInterval)

	for range ticker.C {
		tm.performHealthChecks()
	}
}

func (tm *TunnelManager) performHealthChecks() {
	// Check all active SSH tunnels
	tunnels := tm.sshManager.GetAllTunnels()
	for nodeID, tunnel := range tunnels {
		status := tm.sshManager.CheckTunnelHealth(nodeID)

		// Update database with current status
		var dbStatus string
		switch status {
		case "online":
			dbStatus = "online"
		case "degraded":
			dbStatus = "degraded"
		case "offline":
			dbStatus = "error"
		default:
			dbStatus = "error"
		}

		_, err := tm.db.Exec("UPDATE remote_nodes SET status = $1, ssh_health = $2, last_seen = now() WHERE id = $3",
			dbStatus, status, nodeID)
		if err != nil {
			log.Printf("Warning: Failed to update tunnel status for %s: %v", tunnel.Name, err)
		}

		if status == "offline" || status == "degraded" {
			log.Printf("Tunnel %s (%s) is %s, attempting reconnect", tunnel.Name, nodeID, status)

			// Try to reconnect
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := tm.sshManager.StartTunnel(ctx, tunnel); err != nil {
				log.Printf("Failed to reconnect tunnel %s: %v", tunnel.Name, err)
			} else {
				log.Printf("Successfully reconnected tunnel %s", tunnel.Name)
			}
			cancel()
		}
	}

	// TODO: Check WireGuard peers when implemented
}