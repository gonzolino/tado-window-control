package windowcontrol

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gonzolino/gotado/v2"
	"golang.org/x/oauth2"
)

const (
	secretTadoOAuthToken = "tado_oauth_token"
)

func httpError(w http.ResponseWriter, code int) {
	http.Error(w, http.StatusText(code), code)
}

// handlerSetup holds the common dependencies initialized by initHandler.
type handlerSetup struct {
	ProjectID     string
	SecretManager *SecretManager
	OAuthToken    *oauth2.Token
	AuthConfig    *oauth2.Config
}

// initHandler performs the common setup shared by all HTTP handlers:
// reading env vars, creating the secret manager, validating the auth token,
// and loading the tado OAuth token. It writes an HTTP error and returns nil
// if any step fails.
func initHandler(ctx context.Context, w http.ResponseWriter, authToken string) *handlerSetup {
	if authToken == "" {
		httpError(w, http.StatusForbidden)
		return nil
	}

	projectID, ok := os.LookupEnv("GCP_PROJECT")
	if !ok {
		log.Println("Missing environment variable 'GCP_PROJECT'")
		httpError(w, http.StatusInternalServerError)
		return nil
	}
	tadoClientID, ok := os.LookupEnv("TADO_CLIENT_ID")
	if !ok {
		log.Println("Missing environment variable 'TADO_CLIENT_ID'")
		httpError(w, http.StatusInternalServerError)
		return nil
	}

	secretmanager, err := NewSecretManager(ctx)
	if err != nil {
		log.Printf("Failed to create secretmanager: %v", err)
		httpError(w, http.StatusInternalServerError)
		return nil
	}

	if ok, err := isValidToken(ctx, secretmanager, projectID, authToken); err != nil {
		log.Printf("Failed to get auth tokens: %v", err)
		httpError(w, http.StatusInternalServerError)
		return nil
	} else if !ok {
		httpError(w, http.StatusForbidden)
		return nil
	}

	tokenJSON, err := secretmanager.AccessSecret(ctx, projectID, secretTadoOAuthToken)
	if err != nil {
		log.Printf("Failed to get tado OAuth token: %v", err)
		httpError(w, http.StatusInternalServerError)
		return nil
	}
	var token oauth2.Token
	if err := json.Unmarshal([]byte(tokenJSON), &token); err != nil {
		log.Printf("Failed to parse tado OAuth token: %v", err)
		httpError(w, http.StatusInternalServerError)
		return nil
	}

	config := gotado.AuthConfig(tadoClientID, "offline_access")

	return &handlerSetup{
		ProjectID:     projectID,
		SecretManager: secretmanager,
		OAuthToken:    &token,
		AuthConfig:    config,
	}
}

// persistToken serializes and stores a new OAuth token in Secret Manager.
func (s *handlerSetup) persistToken(ctx context.Context, token *oauth2.Token) error {
	data, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("failed to serialize refreshed tado OAuth token: %w", err)
	}
	if err := s.SecretManager.AddSecretVersion(ctx, s.ProjectID, secretTadoOAuthToken, data); err != nil {
		return fmt.Errorf("failed to persist refreshed tado OAuth token: %w", err)
	}
	return nil
}
