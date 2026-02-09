package config

import (
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

type Config struct {
	// Listener addresses
	HTTPAddr  string
	HTTPSAddr string
	APIAddr   string

	// Database
	DBPath string

	// TLS / ACME
	CFDNSAPIToken  string
	CFEmail        string
	ACMEEmail      string
	LEStaging      bool
	WildcardDomain bool

	// Proxy
	OAuthEncryptionKey string
	ProxyIP            string

	// AdGuard primary
	AdGuardURL  string
	AdGuardUser string
	AdGuardPass string

	// Sync
	SyncInterval  int
	FlattenCNAMEs bool
}

func Load() *Config {
	_ = godotenv.Load()

	return &Config{
		HTTPAddr:  envOr("HTTP_ADDR", ":80"),
		HTTPSAddr: envOr("HTTPS_ADDR", ":443"),
		APIAddr:   envOr("API_ADDR", ":8080"),

		DBPath: envOr("DB_PATH", "nexus.db"),

		CFDNSAPIToken:  os.Getenv("CF_DNS_API_TOKEN"),
		CFEmail:        os.Getenv("CLOUDFLARE_EMAIL"),
		ACMEEmail:      envOr("ACME_EMAIL", "admin@localhost"),
		LEStaging:      false, // controlled via UI toggle, stored in DB
		WildcardDomain: os.Getenv("WILDCARD_DOMAIN_CERT") == "true",

		OAuthEncryptionKey: os.Getenv("OAUTH_ENCRYPTION_KEY"),
		ProxyIP:            os.Getenv("PROXY_IP"),

		AdGuardURL:  os.Getenv("ADGUARD_URL"),
		AdGuardUser: os.Getenv("ADGUARD_USER"),
		AdGuardPass: os.Getenv("ADGUARD_PASS"),

		SyncInterval:  envInt("SYNC_INTERVAL", 300),
		FlattenCNAMEs: envBool("FLATTEN_CNAMES"),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func envBool(key string) bool {
	v := os.Getenv(key)
	return strings.EqualFold(v, "true") || v == "1"
}
