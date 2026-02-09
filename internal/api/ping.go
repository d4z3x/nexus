package api

import (
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

func handlePing(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		jsonError(w, "host parameter required", http.StatusBadRequest)
		return
	}

	if strings.Contains(host, "://") {
		host = strings.TrimPrefix(host, "http://")
		host = strings.TrimPrefix(host, "https://")
	}
	if idx := strings.IndexByte(host, '/'); idx >= 0 {
		host = host[:idx]
	}

	reachable := pingHost(host)

	jsonResponse(w, map[string]interface{}{
		"host":      host,
		"reachable": reachable,
	}, http.StatusOK)
}

func pingHost(host string) bool {
	// Try TCP on common ports
	for _, port := range []string{"443", "80"} {
		addr := host
		if !strings.Contains(host, ":") {
			addr = net.JoinHostPort(host, port)
		}
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			conn.Close()
			return true
		}
	}

	// Fallback to ICMP ping
	cleanHost := host
	if idx := strings.LastIndex(cleanHost, ":"); idx >= 0 {
		cleanHost = cleanHost[:idx]
	}
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "1", "-w", "2000", cleanHost)
	} else {
		cmd = exec.Command("ping", "-c", "1", "-W", "2", cleanHost)
	}
	return cmd.Run() == nil
}
