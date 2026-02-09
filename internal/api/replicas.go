package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/d4z3x/nexus/internal/db"
	"github.com/gorilla/mux"
)

type replicaHandlers struct {
	db *db.DB
}

func (h *replicaHandlers) list(w http.ResponseWriter, r *http.Request) {
	replicas, err := h.db.ListReplicas()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if replicas == nil {
		replicas = []db.Replica{}
	}
	jsonResponse(w, replicas, http.StatusOK)
}

func (h *replicaHandlers) create(w http.ResponseWriter, r *http.Request) {
	var replica db.Replica
	if err := json.NewDecoder(r.Body).Decode(&replica); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if replica.URL == "" || replica.Name == "" {
		jsonError(w, "name and url are required", http.StatusBadRequest)
		return
	}
	if replica.Mode == "" {
		replica.Mode = "rewrites"
	}

	b := make([]byte, 8)
	rand.Read(b)
	replica.ID = hex.EncodeToString(b)

	if err := h.db.CreateReplica(&replica); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, replica, http.StatusCreated)
}

func (h *replicaHandlers) update(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var replica db.Replica
	if err := json.NewDecoder(r.Body).Decode(&replica); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	replica.ID = id
	if err := h.db.UpdateReplica(&replica); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, map[string]string{"status": "updated"}, http.StatusOK)
}

func (h *replicaHandlers) remove(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if err := h.db.DeleteReplica(id); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonResponse(w, map[string]string{"status": "deleted"}, http.StatusOK)
}
