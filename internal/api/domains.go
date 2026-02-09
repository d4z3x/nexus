package api

import (
	"log"
	"net/http"
	"strings"

	"github.com/d4z3x/nexus/internal/cloudflare"
	"github.com/d4z3x/nexus/internal/db"
	"github.com/d4z3x/nexus/internal/dns"
)

type domainHandlers struct {
	db         *db.DB
	cf         *cloudflare.Client
	syncEngine *dns.SyncEngine
}

type domainsResponse struct {
	Zones         []string `json:"zones"`
	DefaultDomain string   `json:"default_domain"`
	ProxyIP       string   `json:"proxy_ip"`
	Error         string   `json:"error,omitempty"`
}

func (h *domainHandlers) list(w http.ResponseWriter, r *http.Request) {
	var zones []string
	var cfError string
	if h.cf != nil && h.cf.Configured() {
		var err error
		zones, err = h.cf.GetZones()
		if err != nil {
			log.Printf("[cloudflare] zone fetch error: %v", err)
			cfError = err.Error()
		}
	}
	if zones == nil {
		zones = []string{}
	}

	defaultDomain := h.detectDefaultDomain()

	proxyIP := ""
	if h.db != nil {
		proxyIP = h.db.GetSetting("proxy_ip")
	}

	jsonResponse(w, domainsResponse{
		Zones:         zones,
		DefaultDomain: defaultDomain,
		ProxyIP:       proxyIP,
		Error:         cfError,
	}, http.StatusOK)
}

func (h *domainHandlers) detectDefaultDomain() string {
	routes, err := h.db.ListRoutes()
	if err != nil {
		return ""
	}
	counts := map[string]int{}
	for _, r := range routes {
		base := parentDomain(r.Hostname)
		if base != "" {
			counts[base]++
		}
	}
	best := ""
	bestCount := 0
	for domain, count := range counts {
		if count > bestCount {
			best = domain
			bestCount = count
		}
	}
	return best
}

func parentDomain(hostname string) string {
	idx := strings.IndexByte(hostname, '.')
	if idx < 0 || idx == len(hostname)-1 {
		return ""
	}
	return hostname[idx+1:]
}
