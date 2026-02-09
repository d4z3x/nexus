package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/d4z3x/nexus/internal/config"
	"github.com/d4z3x/nexus/internal/db"
	"github.com/d4z3x/nexus/internal/dns"
)

type syncHandlers struct {
	engine *dns.SyncEngine
	db     *db.DB
	cfg    *config.Config
}

func (h *syncHandlers) status(w http.ResponseWriter, r *http.Request) {
	if h.engine == nil {
		jsonResponse(w, map[string]interface{}{"enabled": false}, http.StatusOK)
		return
	}
	status := h.engine.GetStatus()
	jsonResponse(w, status, http.StatusOK)
}

func (h *syncHandlers) trigger(w http.ResponseWriter, r *http.Request) {
	if h.engine == nil {
		jsonError(w, "sync not configured", http.StatusServiceUnavailable)
		return
	}

	status := h.engine.GetStatus()
	if status.Running {
		jsonError(w, "sync already in progress", http.StatusConflict)
		return
	}

	go h.engine.RunSync()
	jsonResponse(w, map[string]string{"status": "sync started"}, http.StatusOK)
}

func (h *syncHandlers) setInterval(w http.ResponseWriter, r *http.Request) {
	if h.engine == nil {
		jsonError(w, "sync not configured", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		Seconds int `json:"seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Seconds < 10 {
		jsonError(w, "interval must be at least 10 seconds", http.StatusBadRequest)
		return
	}

	h.engine.SetInterval(time.Duration(req.Seconds) * time.Second)

	jsonResponse(w, map[string]string{"status": "interval updated"}, http.StatusOK)
}

func (h *syncHandlers) updateSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProxyIP   *string `json:"proxy_ip"`
		LEStaging *bool   `json:"le_staging"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if req.ProxyIP != nil {
		if err := h.db.SetSetting("proxy_ip", *req.ProxyIP); err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	if req.LEStaging != nil {
		val := "false"
		if *req.LEStaging {
			val = "true"
		}
		if err := h.db.SetSetting("le_staging", val); err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		h.cfg.LEStaging = *req.LEStaging
	}

	jsonResponse(w, map[string]string{"status": "updated"}, http.StatusOK)
}
