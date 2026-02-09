package proxy

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/d4z3x/nexus/internal/auth"
	"github.com/d4z3x/nexus/internal/db"
)

type Handler struct {
	DB          *db.DB
	OAuthEncKey string
	Transport   http.RoundTripper
	proxyCache  sync.Map
}

func NewHandler(database *db.DB, oauthEncKey string, transport http.RoundTripper) *Handler {
	return &Handler{
		DB:          database,
		OAuthEncKey: oauthEncKey,
		Transport:   transport,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hostname := stripPort(r.Host)

	if cached, ok := h.proxyCache.Load(hostname); ok {
		cached.(http.Handler).ServeHTTP(w, r)
		return
	}

	route, err := h.DB.GetRouteByHostname(hostname)
	if err != nil {
		http.Error(w, "no route configured for "+hostname, http.StatusBadGateway)
		return
	}

	handler, err := h.buildHandler(route)
	if err != nil {
		log.Printf("[proxy] error building handler for %s: %v", hostname, err)
		http.Error(w, "proxy configuration error", http.StatusBadGateway)
		return
	}

	h.proxyCache.Store(hostname, handler)
	handler.ServeHTTP(w, r)
}

func (h *Handler) InvalidateCache(hostname string) {
	h.proxyCache.Delete(hostname)
}

func (h *Handler) InvalidateAll() {
	h.proxyCache.Range(func(key, _ interface{}) bool {
		h.proxyCache.Delete(key)
		return true
	})
}

func (h *Handler) buildHandler(route *db.Route) (http.Handler, error) {
	rawURL := route.TargetURL
	if !strings.Contains(rawURL, "://") {
		rawURL = "http://" + rawURL
	}
	target, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	setProxyHeaders := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host

		if target.Path != "" && target.Path != "/" {
			req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
		}

		if route.PreserveHost {
			req.Host = route.Hostname
		} else {
			req.Host = target.Host
		}

		if clientIP := req.Header.Get("X-Forwarded-For"); clientIP == "" {
			req.Header.Set("X-Forwarded-For", req.RemoteAddr)
		}
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", route.Hostname)
	}

	proxy := &httputil.ReverseProxy{
		Transport: h.Transport,
		Director:  setProxyHeaders,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("[proxy] %s -> %s error: %v", route.Hostname, route.TargetURL, err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isWebSocketUpgrade(r) {
			h.handleWebSocket(w, r, target, route)
			return
		}
		proxy.ServeHTTP(w, r)
	})

	return auth.Middleware(route, h.OAuthEncKey, handler), nil
}

func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Connection"), "upgrade") &&
		strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

func (h *Handler) handleWebSocket(w http.ResponseWriter, r *http.Request, target *url.URL, route *db.Route) {
	wsScheme := "ws"
	if target.Scheme == "https" {
		wsScheme = "wss"
	}

	backendHost := target.Host
	backendPath := r.URL.Path
	if target.Path != "" && target.Path != "/" {
		backendPath = singleJoiningSlash(target.Path, r.URL.Path)
	}

	var backendConn net.Conn
	var err error

	dialAddr := backendHost
	if !strings.Contains(dialAddr, ":") {
		if wsScheme == "wss" {
			dialAddr += ":443"
		} else {
			dialAddr += ":80"
		}
	}

	if wsScheme == "wss" {
		backendConn, err = tls.DialWithDialer(
			&net.Dialer{Timeout: 10 * time.Second},
			"tcp", dialAddr,
			&tls.Config{InsecureSkipVerify: true},
		)
	} else {
		backendConn, err = net.DialTimeout("tcp", dialAddr, 10*time.Second)
	}
	if err != nil {
		log.Printf("[ws] dial %s error: %v", backendHost, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	reqURL := backendPath
	if r.URL.RawQuery != "" {
		reqURL += "?" + r.URL.RawQuery
	}

	var reqBuf []byte
	reqBuf = append(reqBuf, "GET "+reqURL+" HTTP/1.1\r\n"...)
	if route.PreserveHost {
		reqBuf = append(reqBuf, "Host: "+route.Hostname+"\r\n"...)
	} else {
		reqBuf = append(reqBuf, "Host: "+backendHost+"\r\n"...)
	}

	for key, vals := range r.Header {
		for _, val := range vals {
			reqBuf = append(reqBuf, key+": "+val+"\r\n"...)
		}
	}
	reqBuf = append(reqBuf, "X-Forwarded-For: "+r.RemoteAddr+"\r\n"...)
	reqBuf = append(reqBuf, "X-Forwarded-Proto: https\r\n"...)
	reqBuf = append(reqBuf, "X-Forwarded-Host: "+route.Hostname+"\r\n"...)
	reqBuf = append(reqBuf, "\r\n"...)

	if _, err := backendConn.Write(reqBuf); err != nil {
		log.Printf("[ws] write upgrade to %s error: %v", backendHost, err)
		backendConn.Close()
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("[ws] response writer does not support hijacking")
		backendConn.Close()
		http.Error(w, "WebSocket not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("[ws] hijack error: %v", err)
		backendConn.Close()
		return
	}

	go func() {
		io.Copy(clientConn, backendConn)
		clientConn.Close()
	}()
	go func() {
		io.Copy(backendConn, clientConn)
		backendConn.Close()
	}()
}

func stripPort(host string) string {
	if i := strings.LastIndex(host, ":"); i != -1 {
		return host[:i]
	}
	return host
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}
