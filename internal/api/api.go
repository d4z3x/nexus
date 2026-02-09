package api

import (
	"net/http"
	"time"

	"github.com/d4z3x/nexus/internal/adguard"
	"github.com/d4z3x/nexus/internal/cloudflare"
	"github.com/d4z3x/nexus/internal/config"
	"github.com/d4z3x/nexus/internal/db"
	"github.com/d4z3x/nexus/internal/dns"
	"github.com/d4z3x/nexus/internal/proxy"
	nxtls "github.com/d4z3x/nexus/internal/tls"
	"github.com/gorilla/mux"
)

func NewRouter(database *db.DB, tlsManager *nxtls.Manager, proxyHandler *proxy.Handler, adguardClient *adguard.Client, syncEngine *dns.SyncEngine, cfClient *cloudflare.Client, cfg *config.Config) http.Handler {
	r := mux.NewRouter()

	rh := &routeHandlers{db: database, proxyHandler: proxyHandler, adguard: adguardClient, cfg: cfg}
	ch := &certHandlers{db: database, tlsManager: tlsManager}
	hh := &healthHandlers{db: database, cfg: cfg, tlsManager: tlsManager, startTime: time.Now()}
	dh := &domainHandlers{db: database, cf: cfClient, syncEngine: syncEngine}
	rwh := &rewriteHandlers{adguard: adguardClient, syncEngine: syncEngine}
	rph := &replicaHandlers{db: database}
	sh := &syncHandlers{engine: syncEngine, db: database, cfg: cfg}

	api := r.PathPrefix("/api/v1").Subrouter()

	// Proxy routes
	api.HandleFunc("/routes", rh.list).Methods("GET")
	api.HandleFunc("/routes", rh.create).Methods("POST")
	api.HandleFunc("/routes/{id}", rh.get).Methods("GET")
	api.HandleFunc("/routes/{id}", rh.update).Methods("PUT")
	api.HandleFunc("/routes/{id}", rh.delete).Methods("DELETE")

	// Certs
	api.HandleFunc("/certs", ch.list).Methods("GET")
	api.HandleFunc("/certs/{hostname}/renew", ch.renew).Methods("POST")

	// Health
	api.HandleFunc("/health", hh.systemHealth).Methods("GET")
	api.HandleFunc("/health/{id}", hh.routeHealth).Methods("GET")

	// Domains & ping
	api.HandleFunc("/domains", dh.list).Methods("GET")
	api.HandleFunc("/ping", handlePing).Methods("GET")

	// DNS rewrites (direct to AdGuard primary)
	api.HandleFunc("/rewrites", rwh.list).Methods("GET")
	api.HandleFunc("/rewrites", rwh.create).Methods("POST")
	api.HandleFunc("/rewrites", rwh.edit).Methods("PUT")
	api.HandleFunc("/rewrites", rwh.remove).Methods("DELETE")

	// Replicas
	api.HandleFunc("/replicas", rph.list).Methods("GET")
	api.HandleFunc("/replicas", rph.create).Methods("POST")
	api.HandleFunc("/replicas/{id}", rph.update).Methods("PUT")
	api.HandleFunc("/replicas/{id}", rph.remove).Methods("DELETE")

	// Sync
	api.HandleFunc("/sync/status", sh.status).Methods("GET")
	api.HandleFunc("/sync/trigger", sh.trigger).Methods("POST")
	api.HandleFunc("/sync/interval", sh.setInterval).Methods("PUT")
	api.HandleFunc("/settings", sh.updateSettings).Methods("PUT")

	return r
}
