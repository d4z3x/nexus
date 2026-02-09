package auth

import (
	"net/http"
	"strings"
)

func ForwardAuth(cfg map[string]interface{}, next http.Handler) http.Handler {
	authURL, _ := cfg["url"].(string)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if authURL == "" {
			http.Error(w, "forward auth not configured", http.StatusInternalServerError)
			return
		}

		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, authURL, nil)
		if err != nil {
			http.Error(w, "auth request error", http.StatusInternalServerError)
			return
		}

		req.Header.Set("X-Forwarded-Method", r.Method)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", r.Host)
		req.Header.Set("X-Forwarded-Uri", r.RequestURI)
		req.Header.Set("X-Forwarded-For", r.RemoteAddr)

		for _, c := range r.Cookies() {
			req.AddCookie(c)
		}

		if auth := r.Header.Get("Authorization"); auth != "" {
			req.Header.Set("Authorization", auth)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, "auth service unavailable", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			for k, v := range resp.Header {
				for _, vv := range v {
					w.Header().Add(k, vv)
				}
			}
			w.WriteHeader(resp.StatusCode)
			return
		}

		headersToForward := []string{"Remote-User", "Remote-Name", "Remote-Email", "Remote-Groups"}
		for _, h := range headersToForward {
			if v := resp.Header.Get(h); v != "" {
				r.Header.Set(h, v)
			}
		}
		for k, v := range resp.Header {
			if strings.HasPrefix(k, "X-") {
				r.Header.Set(k, v[0])
			}
		}

		next.ServeHTTP(w, r)
	})
}
