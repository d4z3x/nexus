package main

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/d4z3x/nexus/internal/adguard"
	"github.com/d4z3x/nexus/internal/api"
	"github.com/d4z3x/nexus/internal/cloudflare"
	"github.com/d4z3x/nexus/internal/config"
	"github.com/d4z3x/nexus/internal/db"
	"github.com/d4z3x/nexus/internal/dns"
	"github.com/d4z3x/nexus/internal/proxy"
	nxtls "github.com/d4z3x/nexus/internal/tls"
	"github.com/d4z3x/nexus/internal/web"
	"github.com/gorilla/mux"
)

// tlsErrorFilter suppresses noisy TLS handshake errors (EOF, connection reset, etc).
type tlsErrorFilter struct{}

func (f *tlsErrorFilter) Write(p []byte) (n int, err error) {
	msg := string(p)
	if strings.Contains(msg, "TLS handshake error") {
		return len(p), nil
	}
	// Pass through anything else
	log.Print(msg)
	return len(p), nil
}

func main() {
	cfg := config.Load()

	// Set local timezone from TZ env var (godotenv loads after Go inits time.Local)
	if tz := os.Getenv("TZ"); tz != "" {
		if loc, err := time.LoadLocation(tz); err == nil {
			time.Local = loc
		} else {
			log.Printf("warning: invalid TZ %q: %v", tz, err)
		}
	}

	// Open database
	database, err := db.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer database.Close()

	// Store proxy IP in settings if provided via env
	if cfg.ProxyIP != "" {
		database.SetSetting("proxy_ip", cfg.ProxyIP)
	}

	// LE staging from DB (UI toggle is source of truth)
	if v := database.GetSetting("le_staging"); v != "" {
		cfg.LEStaging = v == "true"
	}

	// TLS manager
	tlsManager, err := nxtls.NewManager(cfg, database)
	if err != nil {
		log.Fatalf("tls manager: %v", err)
	}

	// Proxy handler
	transport := proxy.NewTransport()
	proxyHandler := proxy.NewHandler(database, cfg.OAuthEncryptionKey, transport)

	// Cloudflare zones client
	cfClient := cloudflare.NewClient(cfg.CFDNSAPIToken, cfg.CFEmail)

	// AdGuard primary client
	var adguardClient *adguard.Client
	if cfg.AdGuardURL != "" {
		adguardClient = adguard.NewClient(cfg.AdGuardURL, cfg.AdGuardUser, cfg.AdGuardPass)
	}

	// Connectivity checks (non-blocking — don't delay listener startup)
	go func() {
		if cfClient.Configured() {
			zones, err := cfClient.GetZones()
			if err != nil {
				log.Printf("[cloudflare] FAILED to connect: %v", err)
			} else {
				log.Printf("[cloudflare] OK — %d zones found", len(zones))
			}
		} else {
			log.Println("[cloudflare] not configured (no CF_DNS_API_TOKEN)")
		}
		if adguardClient != nil {
			rewrites, err := adguardClient.ListRewrites()
			if err != nil {
				log.Printf("[adguard] FAILED to connect to %s: %v", cfg.AdGuardURL, err)
			} else {
				log.Printf("[adguard] OK — %s (%d rewrites)", cfg.AdGuardURL, len(rewrites))
			}
		} else {
			log.Println("[adguard] not configured (no ADGUARD_URL)")
		}
	}()

	// DNS sync engine
	var syncEngine *dns.SyncEngine
	if adguardClient != nil && adguardClient.Configured() {
		interval := time.Duration(cfg.SyncInterval) * time.Second
		syncEngine = dns.NewSyncEngine(adguardClient, database, interval, cfg.FlattenCNAMEs, cfg.AdGuardURL)
		syncEngine.Start(context.Background())
		defer syncEngine.Stop()
		log.Printf("DNS sync engine started (interval: %ds, CNAME flatten: %v)", cfg.SyncInterval, cfg.FlattenCNAMEs)
	}

	// Health checker
	healthChecker := proxy.NewHealthChecker(database, 60*time.Second)

	// Stop channel for background goroutines
	stop := make(chan struct{})

	// Start background workers
	go tlsManager.StartRenewalLoop(stop)
	go healthChecker.Start(stop)

	// --- Listener 1: HTTP (:80) - redirect to HTTPS ---
	httpServer := &http.Server{
		Addr: cfg.HTTPAddr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			target := "https://" + r.Host + r.RequestURI
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		}),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// --- Listener 2: HTTPS (:443) - reverse proxy ---
	httpsServer := &http.Server{
		Addr:    cfg.HTTPSAddr,
		Handler: proxyHandler,
		TLSConfig: &tls.Config{
			GetCertificate: tlsManager.GetCertificate,
			MinVersion:     tls.VersionTLS12,
		},
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
		ErrorLog:     log.New(&tlsErrorFilter{}, "", 0),
	}

	// --- Listener 3: Management API (:8080) ---
	apiRouter := api.NewRouter(database, tlsManager, proxyHandler, adguardClient, syncEngine, cfClient, cfg)
	mgmtRouter := mux.NewRouter()
	mgmtRouter.PathPrefix("/api/").Handler(apiRouter)
	mgmtRouter.PathPrefix("/").Handler(web.Handler())

	apiServer := &http.Server{
		Addr:         cfg.APIAddr,
		Handler:      mgmtRouter,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// Start all listeners
	go func() {
		log.Printf("HTTP listener on %s (redirect to HTTPS)", cfg.HTTPAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("http server error: %v", err)
		}
	}()

	go func() {
		log.Printf("HTTPS listener on %s (reverse proxy)", cfg.HTTPSAddr)
		if err := httpsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Printf("https server error: %v", err)
		}
	}()

	go func() {
		log.Printf("Management API on %s", cfg.APIAddr)
		if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("api server error: %v", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("shutting down...")
	close(stop)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	httpServer.Shutdown(ctx)
	httpsServer.Shutdown(ctx)
	apiServer.Shutdown(ctx)

	log.Println("shutdown complete")
}
