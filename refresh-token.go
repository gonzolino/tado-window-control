package windowcontrol

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gonzolino/gotado/v2"
	"golang.org/x/oauth2"
)

// RefreshTokenRequest holds the authentication token for the refresh request
type RefreshTokenRequest struct {
	Token string `json:"token"`
}

// RefreshToken refreshes the tado° OAuth token and stores the new token in Secret Manager
func RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest)
		return
	}
	if req.Token == "" {
		httpError(w, http.StatusForbidden)
		return
	}

	projectID, ok := os.LookupEnv("GCP_PROJECT")
	if !ok {
		log.Println("Missing environment variable 'GCP_PROJECT'")
		httpError(w, http.StatusInternalServerError)
		return
	}
	tadoClientID, ok := os.LookupEnv("TADO_CLIENT_ID")
	if !ok {
		log.Println("Missing environment variable 'TADO_CLIENT_ID'")
		httpError(w, http.StatusInternalServerError)
		return
	}

	ctx := r.Context()
	secretmanager, err := NewSecretManager(ctx)
	if err != nil {
		log.Printf("Failed to create secretmanager: %v", err)
		httpError(w, http.StatusInternalServerError)
		return
	}

	if ok, err := isValidToken(ctx, secretmanager, projectID, req.Token); err != nil {
		log.Printf("Failed to get auth tokens: %v", err)
		httpError(w, http.StatusInternalServerError)
		return
	} else if !ok {
		httpError(w, http.StatusForbidden)
		return
	}

	tokenJSON, err := secretmanager.AccessSecret(ctx, projectID, secretTadoOAuthToken)
	if err != nil {
		log.Printf("Failed to get tado OAuth token: %v", err)
		httpError(w, http.StatusInternalServerError)
		return
	}
	var token oauth2.Token
	if err := json.Unmarshal([]byte(tokenJSON), &token); err != nil {
		log.Printf("Failed to parse tado OAuth token: %v", err)
		httpError(w, http.StatusInternalServerError)
		return
	}

	config := gotado.AuthConfig(tadoClientID, "offline_access")
	newToken, err := config.TokenSource(ctx, &token).Token()
	if err != nil {
		log.Printf("Failed to refresh tado OAuth token: %v", err)
		httpError(w, http.StatusInternalServerError)
		return
	}

	data, err := json.Marshal(newToken)
	if err != nil {
		log.Printf("Failed to serialize refreshed tado OAuth token: %v", err)
		httpError(w, http.StatusInternalServerError)
		return
	}
	if err := secretmanager.AddSecretVersion(ctx, projectID, secretTadoOAuthToken, data); err != nil {
		log.Printf("Failed to persist refreshed tado OAuth token: %v", err)
		httpError(w, http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(w, "OK")
}
