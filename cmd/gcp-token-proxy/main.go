package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type tokenRequest struct {
	ClientEmail    string `json:"client_email"`
	PrivateKey     string `json:"private_key"`
	TokenURI       string `json:"token_uri"`
	TargetAudience string `json:"target_audience"`
}

type cachedToken struct {
	IDToken string
	Expiry  time.Time
}

var (
	cache   = map[string]cachedToken{}
	cacheMu sync.RWMutex
)

func main() {
	http.HandleFunc("/token", handleToken)
	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req tokenRequest
	if r.Body != nil {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			jsonError(w, "failed to read body", http.StatusBadRequest)
			return
		}
		if len(body) > 0 {
			if err := json.Unmarshal(body, &req); err != nil {
				jsonError(w, "invalid JSON", http.StatusBadRequest)
				return
			}
		}
	}

	// Merge with env var defaults
	if req.ClientEmail == "" {
		req.ClientEmail = os.Getenv("GCP_CLIENT_EMAIL")
	}
	if req.PrivateKey == "" {
		req.PrivateKey = os.Getenv("GCP_PRIVATE_KEY")
	}
	if req.TargetAudience == "" {
		req.TargetAudience = os.Getenv("GCP_TARGET_AUDIENCE")
	}
	// Hardcode token URI to prevent Srequest forgery attacks
	req.TokenURI = "https://oauth2.googleapis.com/token"

	// Validate required fields
	if req.ClientEmail == "" || req.PrivateKey == "" || req.TargetAudience == "" {
		jsonError(w, "missing required fields: client_email, private_key, target_audience", http.StatusBadRequest)
		return
	}

	// Check cache
	cacheKey := req.ClientEmail + "|" + req.TargetAudience
	cacheMu.RLock()
	if cached, ok := cache[cacheKey]; ok && time.Now().Add(5*time.Minute).Before(cached.Expiry) {
		cacheMu.RUnlock()
		writeJSON(w, map[string]string{"id_token": cached.IDToken})
		return
	}
	cacheMu.RUnlock()

	// Build and sign JWT
	now := time.Now()
	header := base64url([]byte(`{"alg":"RS256","typ":"JWT"}`))

	payload, err := json.Marshal(map[string]any{
		"iss":             req.ClientEmail,
		"sub":             req.ClientEmail,
		"aud":             req.TokenURI,
		"iat":             now.Unix(),
		"exp":             now.Add(time.Hour).Unix(),
		"target_audience": req.TargetAudience,
	})
	if err != nil {
		jsonError(w, "failed to build JWT payload", http.StatusInternalServerError)
		return
	}

	signingInput := header + "." + base64url(payload)

	key, err := parsePrivateKey(req.PrivateKey)
	if err != nil {
		jsonError(w, fmt.Sprintf("invalid private key: %v", err), http.StatusBadRequest)
		return
	}

	hash := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		jsonError(w, fmt.Sprintf("signing failed: %v", err), http.StatusInternalServerError)
		return
	}

	signedJWT := signingInput + "." + base64url(sig)

	// Exchange for identity token
	resp, err := http.PostForm(req.TokenURI, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {signedJWT},
	})
	if err != nil {
		jsonError(w, fmt.Sprintf("token exchange failed: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		jsonError(w, "failed to read token response", http.StatusBadGateway)
		return
	}

	if resp.StatusCode != http.StatusOK {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprintf(w, `{"error":"token endpoint returned %d","details":%s}`, resp.StatusCode, respBody)
		return
	}

	var tokenResp struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(respBody, &tokenResp); err != nil || tokenResp.IDToken == "" {
		jsonError(w, "no id_token in response", http.StatusBadGateway)
		return
	}

	// Cache the token — decode exp from the JWT payload
	if exp, err := extractExp(tokenResp.IDToken); err == nil {
		cacheMu.Lock()
		cache[cacheKey] = cachedToken{IDToken: tokenResp.IDToken, Expiry: exp}
		cacheMu.Unlock()
	}

	writeJSON(w, map[string]string{"id_token": tokenResp.IDToken})
}

func base64url(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

func parsePrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS1 as fallback
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not RSA")
	}
	return rsaKey, nil
}

func extractExp(token string) (time.Time, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, fmt.Errorf("invalid JWT")
	}
	// Add padding if needed
	payload := parts[1]
	if m := len(payload) % 4; m != 0 {
		payload += strings.Repeat("=", 4-m)
	}
	data, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return time.Time{}, err
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(data, &claims); err != nil {
		return time.Time{}, err
	}
	return time.Unix(claims.Exp, 0), nil
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
