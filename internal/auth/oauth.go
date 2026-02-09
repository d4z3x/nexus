package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func OAuthAuth(cfg map[string]interface{}, encKeyHex string, next http.Handler) http.Handler {
	issuer, _ := cfg["issuer"].(string)
	clientID, _ := cfg["client_id"].(string)
	clientSecret, _ := cfg["client_secret"].(string)
	redirectURI, _ := cfg["redirect_uri"].(string)
	scopes, _ := cfg["scopes"].(string)
	if scopes == "" {
		scopes = "openid profile email"
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if issuer == "" || clientID == "" {
			http.Error(w, "oauth not configured", http.StatusInternalServerError)
			return
		}

		if r.URL.Path == "/_oauth/callback" {
			handleOAuthCallback(w, r, issuer, clientID, clientSecret, redirectURI, encKeyHex)
			return
		}

		cookie, err := r.Cookie("_nexus_oauth")
		if err == nil {
			session, err := decryptSession(cookie.Value, encKeyHex)
			if err == nil && session.ExpiresAt.After(time.Now()) {
				r.Header.Set("Remote-User", session.Email)
				next.ServeHTTP(w, r)
				return
			}
		}

		disc, err := discoverOIDC(issuer)
		if err != nil {
			http.Error(w, "oidc discovery failed", http.StatusBadGateway)
			return
		}

		state := base64.URLEncoding.EncodeToString([]byte(r.URL.RequestURI()))
		authURL := fmt.Sprintf("%s?response_type=code&client_id=%s&redirect_uri=%s&scope=%s&state=%s",
			disc.AuthorizationEndpoint, clientID, redirectURI, strings.ReplaceAll(scopes, " ", "+"), state)
		http.Redirect(w, r, authURL, http.StatusFound)
	})
}

type oauthSession struct {
	Email     string    `json:"email"`
	ExpiresAt time.Time `json:"expires_at"`
}

type oidcDiscovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

func discoverOIDC(issuer string) (*oidcDiscovery, error) {
	resp, err := http.Get(issuer + "/.well-known/openid-configuration")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var d oidcDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, err
	}
	return &d, nil
}

func handleOAuthCallback(w http.ResponseWriter, r *http.Request, issuer, clientID, clientSecret, redirectURI, encKeyHex string) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	disc, err := discoverOIDC(issuer)
	if err != nil {
		http.Error(w, "oidc discovery failed", http.StatusBadGateway)
		return
	}

	tokenResp, err := http.PostForm(disc.TokenEndpoint, map[string][]string{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	})
	if err != nil {
		http.Error(w, "token exchange failed", http.StatusBadGateway)
		return
	}
	defer tokenResp.Body.Close()

	var tokenData struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenData); err != nil {
		http.Error(w, "token parse failed", http.StatusBadGateway)
		return
	}

	req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, disc.UserinfoEndpoint, nil)
	req.Header.Set("Authorization", "Bearer "+tokenData.AccessToken)
	uiResp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "userinfo failed", http.StatusBadGateway)
		return
	}
	defer uiResp.Body.Close()

	var userinfo struct {
		Email string `json:"email"`
		Sub   string `json:"sub"`
	}
	if err := json.NewDecoder(uiResp.Body).Decode(&userinfo); err != nil {
		http.Error(w, "userinfo parse failed", http.StatusBadGateway)
		return
	}

	email := userinfo.Email
	if email == "" {
		email = userinfo.Sub
	}

	session := oauthSession{
		Email:     email,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	encrypted, err := encryptSession(session, encKeyHex)
	if err != nil {
		http.Error(w, "session encryption failed", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "_nexus_oauth",
		Value:    encrypted,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400,
	})

	state := r.URL.Query().Get("state")
	originalURL := "/"
	if decoded, err := base64.URLEncoding.DecodeString(state); err == nil && len(decoded) > 0 {
		originalURL = string(decoded)
	}
	http.Redirect(w, r, originalURL, http.StatusFound)
}

func encryptSession(session oauthSession, keyHex string) (string, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 32 {
		return "", fmt.Errorf("invalid encryption key")
	}

	plaintext, _ := json.Marshal(session)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func decryptSession(encrypted, keyHex string) (*oauthSession, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("invalid encryption key")
	}

	data, err := base64.URLEncoding.DecodeString(encrypted)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(data) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	var session oauthSession
	if err := json.Unmarshal(plaintext, &session); err != nil {
		return nil, err
	}
	return &session, nil
}
