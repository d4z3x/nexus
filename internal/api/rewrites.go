package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/d4z3x/nexus/internal/adguard"
	"github.com/d4z3x/nexus/internal/dns"
)

type rewriteHandlers struct {
	adguard    *adguard.Client
	syncEngine *dns.SyncEngine
}

func (h *rewriteHandlers) list(w http.ResponseWriter, r *http.Request) {
	if h.adguard == nil || !h.adguard.Configured() {
		jsonResponse(w, []adguard.Rewrite{}, http.StatusOK)
		return
	}

	rewrites, err := h.adguard.ListRewrites()
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadGateway)
		return
	}
	if rewrites == nil {
		rewrites = []adguard.Rewrite{}
	}
	jsonResponse(w, rewrites, http.StatusOK)
}

func (h *rewriteHandlers) create(w http.ResponseWriter, r *http.Request) {
	if h.adguard == nil || !h.adguard.Configured() {
		jsonError(w, "AdGuard not configured", http.StatusServiceUnavailable)
		return
	}

	var rw adguard.Rewrite
	if err := json.NewDecoder(r.Body).Decode(&rw); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if rw.Domain == "" || rw.Answer == "" {
		jsonError(w, "domain and answer are required", http.StatusBadRequest)
		return
	}

	if err := h.adguard.AddRewrite(rw); err != nil {
		jsonError(w, err.Error(), http.StatusBadGateway)
		return
	}

	if h.syncEngine != nil {
		go h.syncEngine.RunSync()
	}

	jsonResponse(w, map[string]string{"status": "added"}, http.StatusCreated)
}

type editRewriteRequest struct {
	Old adguard.Rewrite `json:"old"`
	New adguard.Rewrite `json:"new"`
}

func (h *rewriteHandlers) edit(w http.ResponseWriter, r *http.Request) {
	if h.adguard == nil || !h.adguard.Configured() {
		jsonError(w, "AdGuard not configured", http.StatusServiceUnavailable)
		return
	}

	var req editRewriteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.New.Domain == "" || req.New.Answer == "" {
		jsonError(w, "new domain and answer are required", http.StatusBadRequest)
		return
	}

	if err := h.adguard.DeleteRewrite(req.Old); err != nil {
		jsonError(w, fmt.Sprintf("delete old: %v", err), http.StatusBadGateway)
		return
	}

	if err := h.adguard.AddRewrite(req.New); err != nil {
		h.adguard.AddRewrite(req.Old) // rollback
		jsonError(w, fmt.Sprintf("add new: %v", err), http.StatusBadGateway)
		return
	}

	if h.syncEngine != nil {
		go h.syncEngine.RunSync()
	}

	jsonResponse(w, map[string]string{"status": "updated"}, http.StatusOK)
}

func (h *rewriteHandlers) remove(w http.ResponseWriter, r *http.Request) {
	if h.adguard == nil || !h.adguard.Configured() {
		jsonError(w, "AdGuard not configured", http.StatusServiceUnavailable)
		return
	}

	var rw adguard.Rewrite
	if err := json.NewDecoder(r.Body).Decode(&rw); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if err := h.adguard.DeleteRewrite(rw); err != nil {
		jsonError(w, err.Error(), http.StatusBadGateway)
		return
	}

	if h.syncEngine != nil {
		go h.syncEngine.RunSync()
	}

	jsonResponse(w, map[string]string{"status": "deleted"}, http.StatusOK)
}
