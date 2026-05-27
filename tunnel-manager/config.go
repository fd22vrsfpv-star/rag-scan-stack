package main

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenAddr      string `yaml:"listen_addr"`
	DatabaseURL     string `yaml:"database_url"`
	SSHKeysDir      string `yaml:"ssh_keys_dir"`
	WireGuardConfig string `yaml:"wireguard_config"`

	// Port allocation ranges
	SSHPortStart       int `yaml:"ssh_port_start"`
	SSHPortEnd         int `yaml:"ssh_port_end"`
	WireGuardPortStart int `yaml:"wireguard_port_start"`
	WireGuardPortEnd   int `yaml:"wireguard_port_end"`

	// Health monitoring
	HealthCheckInterval int `yaml:"health_check_interval"`
	ReconnectAttempts   int `yaml:"reconnect_attempts"`
	BackoffThreshold    int `yaml:"backoff_threshold"`

	// WireGuard settings
	WireGuardNetwork    string `yaml:"wireguard_network"`
	WireGuardServerPort int    `yaml:"wireguard_server_port"`

	// WSL2 specific settings
	WindowsWireGuardIntegration string `yaml:"windows_wireguard_integration"`

	// Logging
	LogLevel string `yaml:"log_level"`
}

func LoadConfig(configPath string) (*Config, error) {
	// Default configuration
	config := &Config{
		ListenAddr:      "0.0.0.0:8027",
		DatabaseURL:     "postgresql://app:app@localhost:5432/scans",
		SSHKeysDir:      "/etc/tunnel-manager/ssh-keys",
		WireGuardConfig: "/etc/tunnel-manager/wireguard",

		SSHPortStart:       10120,
		SSHPortEnd:         10149,
		WireGuardPortStart: 10150,
		WireGuardPortEnd:   10199,

		HealthCheckInterval: 60,
		ReconnectAttempts:   3,
		BackoffThreshold:    5,

		WireGuardNetwork:    "10.66.0.0/24",
		WireGuardServerPort: 51820,

		WindowsWireGuardIntegration: "auto",
		LogLevel:                    "info",
	}

	// Load from file if it exists
	if configPath != "" && fileExists(configPath) {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}

		if err := yaml.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}
	}

	// Override with environment variables
	config.applyEnvironmentOverrides()

	return config, nil
}

func (c *Config) applyEnvironmentOverrides() {
	if dbURL := os.Getenv("DATABASE_URL"); dbURL != "" {
		c.DatabaseURL = dbURL
	}
	if dbURL := os.Getenv("DB_DSN"); dbURL != "" {
		c.DatabaseURL = dbURL
	}
	if keysDir := os.Getenv("SSH_KEYS_DIR"); keysDir != "" {
		c.SSHKeysDir = keysDir
	}
	if logLevel := os.Getenv("LOG_LEVEL"); logLevel != "" {
		c.LogLevel = logLevel
	}
}

func (c *Config) IsWSL() bool {
	if c.WindowsWireGuardIntegration == "force" {
		return true
	}
	if c.WindowsWireGuardIntegration == "disable" {
		return false
	}

	// Auto-detect WSL2
	if content, err := os.ReadFile("/proc/version"); err == nil {
		versionStr := strings.ToLower(string(content))
		return strings.Contains(versionStr, "wsl2") || strings.Contains(versionStr, "microsoft")
	}

	return false
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}