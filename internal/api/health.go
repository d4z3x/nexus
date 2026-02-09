package api

import (
	"net/http"
	"runtime"
	"strconv"
	"time"

	"github.com/d4z3x/nexus/internal/config"
	"github.com/d4z3x/nexus/internal/db"
	nxtls "github.com/d4z3x/nexus/internal/tls"
	"github.com/gorilla/mux"
)

type healthHandlers struct {
	db         *db.DB
	cfg        *config.Config
	tlsManager *nxtls.Manager
	startTime  time.Time
}

func (h *healthHandlers) systemHealth(w http.ResponseWriter, r *http.Request) {
	routeCount, _ := h.db.RouteCount()
	certCount, _ := h.db.CertCount()
	replicaCount, _ := h.db.ReplicaCount()

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	provisionErrors := h.tlsManager.GetProvisionErrors()
	if provisionErrors == nil {
		provisionErrors = []nxtls.ProvisionError{}
	}

	data := map[string]interface{}{
		"uptime_seconds":   int(time.Since(h.startTime).Seconds()),
		"routes":           routeCount,
		"certs":            certCount,
		"replicas":         replicaCount,
		"goroutines":       runtime.NumGoroutine(),
		"memory_mb":        mem.Alloc / 1024 / 1024,
		"le_staging":       h.cfg.LEStaging,
		"wildcard":         h.cfg.WildcardDomain,
		"dns_enabled":      h.cfg.AdGuardURL != "",
		"provision_errors": provisionErrors,
	}
	jsonResponse(w, data, http.StatusOK)
}

func (h *healthHandlers) routeHealth(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(mux.Vars(r)["id"], 10, 64)
	if err != nil {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}

	checks, err := h.db.GetHealthChecks(uint(id))
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if checks == nil {
		checks = []db.HealthCheck{}
	}
	jsonResponse(w, checks, http.StatusOK)
}
