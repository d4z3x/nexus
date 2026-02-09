package api

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"time"

	"github.com/d4z3x/nexus/internal/db"
	nxtls "github.com/d4z3x/nexus/internal/tls"
	"github.com/gorilla/mux"
)

type certHandlers struct {
	db         *db.DB
	tlsManager *nxtls.Manager
}

type certInfo struct {
	Hostname  string    `json:"hostname"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	IsStaging bool      `json:"is_staging"`
	Trusted   bool      `json:"trusted"`
	Issuer    string    `json:"issuer"`
}

func (h *certHandlers) list(w http.ResponseWriter, r *http.Request) {
	certs, err := h.db.ListCerts()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	result := make([]certInfo, 0, len(certs))
	for _, c := range certs {
		ci := certInfo{
			Hostname:  c.Hostname,
			NotBefore: c.NotBefore,
			NotAfter:  c.NotAfter,
			IsStaging: c.IsStaging,
		}

		full, err := h.db.GetCert(c.Hostname)
		if err == nil {
			ci.Trusted, ci.Issuer = verifyCert(full.CertPEM)
		}

		result = append(result, ci)
	}

	jsonResponse(w, result, http.StatusOK)
}

// verifyCert parses the PEM and verifies the chain against system roots.
func verifyCert(certPEM string) (trusted bool, issuer string) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return false, ""
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, ""
	}

	issuer = cert.Issuer.CommonName

	_, err = cert.Verify(x509.VerifyOptions{})
	return err == nil, issuer
}

func (h *certHandlers) renew(w http.ResponseWriter, r *http.Request) {
	hostname := mux.Vars(r)["hostname"]
	if hostname == "" {
		jsonError(w, "hostname required", http.StatusBadRequest)
		return
	}

	if err := h.tlsManager.ForceRenew(hostname); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, map[string]string{"status": "renewed", "hostname": hostname}, http.StatusOK)
}
