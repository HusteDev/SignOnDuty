package config

import (
	"os"
)

type Config struct {
	// Server
	ServerHost string
	ServerPort string

	// TLS
	TLSCertFile string
	TLSKeyFile  string

	// Database
	DatabaseURL string

	// JWT
	JWTSecret string

	// Environment
	Environment string

	// CORS
	AllowedOrigins string
}

func Load() *Config {
	return &Config{
		ServerHost: getEnv("SERVER_HOST", "0.0.0.0"),
		ServerPort: getEnv("SERVER_PORT", "8443"),

		TLSCertFile: getEnv("TLS_CERT_FILE", "/etc/signonduty/tls.crt"),
		TLSKeyFile:  getEnv("TLS_KEY_FILE", "/etc/signonduty/tls.key"),

		DatabaseURL: getEnv("DATABASE_URL", "postgres://user:password@localhost:5432/signonduty"),

		JWTSecret: getEnv("JWT_SECRET", "your-secret-key-change-in-production"),

		Environment: getEnv("ENVIRONMENT", "production"),

		AllowedOrigins: getEnv("ALLOWED_ORIGINS", "https://signonduty.mil"),
	}
}

func getEnv(key, defaultVal string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultVal
}
