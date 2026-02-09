package auth

import (
	"encoding/json"
	"net/http"

	"github.com/d4z3x/nexus/internal/db"
)

func Middleware(route *db.Route, oauthEncKey string, next http.Handler) http.Handler {
	cfg := parseAuthConfig(route.AuthConfig)

	switch route.AuthType {
	case "forward":
		return ForwardAuth(cfg, next)
	case "oauth":
		return OAuthAuth(cfg, oauthEncKey, next)
	case "basic":
		return BasicAuth(cfg, next)
	default:
		return next
	}
}

func parseAuthConfig(raw string) map[string]interface{} {
	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return map[string]interface{}{}
	}
	return cfg
}
