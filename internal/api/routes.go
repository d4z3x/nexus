package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"github.com/d4z3x/nexus/internal/adguard"
	"github.com/d4z3x/nexus/internal/config"
	"github.com/d4z3x/nexus/internal/db"
	"github.com/d4z3x/nexus/internal/proxy"
	"github.com/gorilla/mux"
)

type routeHandlers struct {
	db           *db.DB
	proxyHandler *proxy.Handler
	adguard      *adguard.Client
	cfg          *config.Config
}

type dnsResult struct {
	Primary       bool     `json:"primary"`
	PrimaryError  string   `json:"primary_error,omitempty"`
	Replicas      int      `json:"replicas"`
	ReplicaErrors []string `json:"replica_errors,omitempty"`
}

// addDNSRewrite adds a rewrite to the primary AdGuard and all replicas.
func (h *routeHandlers) addDNSRewrite(hostname, answer string) *dnsResult {
	rw := adguard.Rewrite{Domain: hostname, Answer: answer}
	result := &dnsResult{}

	// Primary
	if h.adguard != nil && h.adguard.Configured() {
		if err := h.adguard.AddRewrite(rw); err != nil {
			log.Printf("[dns] primary: failed to add rewrite for %s: %v", hostname, err)
			result.PrimaryError = err.Error()
		} else {
			log.Printf("[dns] primary: added rewrite %s -> %s", hostname, answer)
			result.Primary = true
		}
	}

	// Replicas
	replicas, err := h.db.ListReplicas()
	if err != nil {
		log.Printf("[dns] failed to list replicas: %v", err)
		return result
	}
	for _, r := range replicas {
		if r.Mode == "blocklist" {
			continue
		}
		client := adguard.NewClient(r.URL, r.Username, r.Password)
		if err := client.AddRewrite(rw); err != nil {
			log.Printf("[dns] replica %s: failed to add rewrite for %s: %v", r.Name, hostname, err)
			result.ReplicaErrors = append(result.ReplicaErrors, r.Name+": "+err.Error())
		} else {
			log.Printf("[dns] replica %s: added rewrite %s -> %s", r.Name, hostname, answer)
			result.Replicas++
		}
	}
	return result
}

// deleteDNSRewrite removes a rewrite from the primary AdGuard and all replicas.
func (h *routeHandlers) deleteDNSRewrite(hostname, answer string) {
	rw := adguard.Rewrite{Domain: hostname, Answer: answer}

	if h.adguard != nil && h.adguard.Configured() {
		if err := h.adguard.DeleteRewrite(rw); err != nil {
			log.Printf("[dns] primary: failed to delete rewrite for %s: %v", hostname, err)
		} else {
			log.Printf("[dns] primary: deleted rewrite %s", hostname)
		}
	}

	replicas, err := h.db.ListReplicas()
	if err != nil {
		log.Printf("[dns] failed to list replicas: %v", err)
		return
	}
	for _, r := range replicas {
		if r.Mode == "blocklist" {
			continue
		}
		client := adguard.NewClient(r.URL, r.Username, r.Password)
		if err := client.DeleteRewrite(rw); err != nil {
			log.Printf("[dns] replica %s: failed to delete rewrite for %s: %v", r.Name, hostname, err)
		} else {
			log.Printf("[dns] replica %s: deleted rewrite %s", r.Name, hostname)
		}
	}
}

func (h *routeHandlers) list(w http.ResponseWriter, r *http.Request) {
	routes, err := h.db.ListRoutes()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if routes == nil {
		routes = []db.Route{}
	}
	jsonResponse(w, routes, http.StatusOK)
}

func (h *routeHandlers) create(w http.ResponseWriter, r *http.Request) {
	var route db.Route
	if err := json.NewDecoder(r.Body).Decode(&route); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if route.Hostname == "" || route.TargetURL == "" {
		jsonError(w, "hostname and target_url are required", http.StatusBadRequest)
		return
	}
	if route.AuthType == "" {
		route.AuthType = "none"
	}
	if route.AuthConfig == "" {
		route.AuthConfig = "{}"
	}

	if err := h.db.CreateRoute(&route); err != nil {
		jsonError(w, err.Error(), http.StatusConflict)
		return
	}

	h.proxyHandler.InvalidateCache(route.Hostname)

	var dns *dnsResult
	if h.cfg.ProxyIP != "" {
		dns = h.addDNSRewrite(route.Hostname, h.cfg.ProxyIP)
	}

	jsonResponse(w, map[string]interface{}{"route": route, "dns": dns}, http.StatusCreated)
}

func (h *routeHandlers) get(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(mux.Vars(r)["id"], 10, 64)
	if err != nil {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}

	route, err := h.db.GetRoute(uint(id))
	if err != nil {
		jsonError(w, "route not found", http.StatusNotFound)
		return
	}
	jsonResponse(w, route, http.StatusOK)
}

func (h *routeHandlers) update(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(mux.Vars(r)["id"], 10, 64)
	if err != nil {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}

	existing, err := h.db.GetRoute(uint(id))
	if err != nil {
		jsonError(w, "route not found", http.StatusNotFound)
		return
	}

	oldHostname := existing.Hostname

	var update db.Route
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if update.Hostname != "" {
		existing.Hostname = update.Hostname
	}
	if update.TargetURL != "" {
		existing.TargetURL = update.TargetURL
	}
	if update.AuthType != "" {
		existing.AuthType = update.AuthType
	}
	if update.AuthConfig != "" {
		existing.AuthConfig = update.AuthConfig
	}
	existing.TLSEnabled = update.TLSEnabled
	existing.PreserveHost = update.PreserveHost
	existing.Enabled = update.Enabled

	if err := h.db.UpdateRoute(existing); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.proxyHandler.InvalidateCache(oldHostname)
	h.proxyHandler.InvalidateCache(existing.Hostname)

	if oldHostname != existing.Hostname && h.cfg.ProxyIP != "" {
		h.deleteDNSRewrite(oldHostname, h.cfg.ProxyIP)
		h.addDNSRewrite(existing.Hostname, h.cfg.ProxyIP)
	}

	jsonResponse(w, existing, http.StatusOK)
}

func (h *routeHandlers) delete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(mux.Vars(r)["id"], 10, 64)
	if err != nil {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}

	route, err := h.db.GetRoute(uint(id))
	if err != nil {
		jsonError(w, "route not found", http.StatusNotFound)
		return
	}

	if err := h.db.DeleteRoute(uint(id)); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.proxyHandler.InvalidateCache(route.Hostname)

	if h.cfg.ProxyIP != "" {
		h.deleteDNSRewrite(route.Hostname, h.cfg.ProxyIP)
	}

	w.WriteHeader(http.StatusNoContent)
}

func jsonResponse(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, msg string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
