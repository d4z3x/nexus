package proxy

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/d4z3x/nexus/internal/db"
)

type Transport struct {
	inner http.RoundTripper
}

func NewTransport() *Transport {
	return &Transport{
		inner: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.inner.RoundTrip(req)
}

type HealthChecker struct {
	DB       *db.DB
	Interval time.Duration
	client   *http.Client
}

func NewHealthChecker(database *db.DB, interval time.Duration) *HealthChecker {
	return &HealthChecker{
		DB:       database,
		Interval: interval,
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (hc *HealthChecker) Start(stop <-chan struct{}) {
	ticker := time.NewTicker(hc.Interval)
	defer ticker.Stop()

	hc.checkAll()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			hc.checkAll()
		}
	}
}

func (hc *HealthChecker) checkAll() {
	routes, err := hc.DB.ListRoutes()
	if err != nil {
		log.Printf("[health] error listing routes: %v", err)
		return
	}

	for _, route := range routes {
		if !route.Enabled {
			continue
		}
		go hc.check(route)
	}
}

func (hc *HealthChecker) check(route db.Route) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, normalizeURL(route.TargetURL), nil)
	if err != nil {
		hc.record(route.ID, 0, 0)
		return
	}
	req.Header.Set("User-Agent", "nexus-healthcheck/1.0")

	start := time.Now()
	resp, err := hc.client.Do(req)
	latency := time.Since(start).Milliseconds()

	if err != nil {
		hc.record(route.ID, 0, int(latency))
		return
	}
	defer resp.Body.Close()

	hc.record(route.ID, resp.StatusCode, int(latency))
}

func normalizeURL(raw string) string {
	if !strings.Contains(raw, "://") {
		return "http://" + raw
	}
	return raw
}

func (hc *HealthChecker) record(routeID uint, status, latencyMs int) {
	if err := hc.DB.InsertHealthCheck(routeID, status, latencyMs); err != nil {
		log.Printf("[health] error recording check for route %d: %v", routeID, err)
	}
}
