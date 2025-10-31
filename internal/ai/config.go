package ai

import (
	"fmt"
	"os"
	"strconv"
)

// Config holds AI service configuration
type Config struct {
	Enabled      bool
	APIEndpoint  string
	APIToken     string
	Model        string
	CacheEnabled bool
	MaxRetries   int
	TimeoutSec   int
}

// LoadConfig loads AI configuration from environment variables
func LoadConfig() (*Config, error) {
	config := &Config{
		Enabled:      getEnvBool("AI_ENABLED", false),
		APIEndpoint:  getEnv("OPENWEBUI_URL", ""),
		APIToken:     getEnv("OPENWEBUI_TOKEN", ""),
		Model:        getEnv("AI_MODEL", "gpt-4"),
		CacheEnabled: getEnvBool("AI_CACHE_ENABLED", true),
		MaxRetries:   getEnvInt("AI_MAX_RETRIES", 3),
		TimeoutSec:   getEnvInt("AI_TIMEOUT_SEC", 30),
	}

	// Validate required fields if AI is enabled
	if config.Enabled {
		if config.APIEndpoint == "" {
			return nil, fmt.Errorf("AI_ENABLED is true but OPENWEBUI_URL is not set")
		}
		if config.APIToken == "" {
			return nil, fmt.Errorf("AI_ENABLED is true but OPENWEBUI_TOKEN is not set")
		}
	}

	return config, nil
}

// Helper functions to read environment variables
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if b, err := strconv.ParseBool(value); err == nil {
			return b
		}
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return defaultValue
}
