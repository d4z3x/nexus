package auth

import (
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

func BasicAuth(cfg map[string]interface{}, next http.Handler) http.Handler {
	usersRaw, _ := cfg["users"].(map[string]interface{})
	users := make(map[string]string)
	for k, v := range usersRaw {
		if s, ok := v.(string); ok {
			users[k] = s
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(users) == 0 {
			http.Error(w, "basic auth not configured", http.StatusInternalServerError)
			return
		}

		username, password, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="nexus"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		hash, exists := users[username]
		if !exists {
			w.Header().Set("WWW-Authenticate", `Basic realm="nexus"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
			w.Header().Set("WWW-Authenticate", `Basic realm="nexus"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		r.Header.Set("Remote-User", username)
		next.ServeHTTP(w, r)
	})
}
