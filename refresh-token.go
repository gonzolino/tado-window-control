package windowcontrol

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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

	ctx := r.Context()

	setup := initHandler(ctx, w, req.Token)
	if setup == nil {
		return
	}
	newToken, err := setup.AuthConfig.TokenSource(ctx, setup.OAuthToken).Token()
	if err != nil {
		log.Printf("Failed to refresh tado OAuth token: %v", err)
		httpError(w, http.StatusInternalServerError)
		return
	}

	if err := setup.persistToken(ctx, newToken); err != nil {
		log.Printf("Failed to persist refreshed tado OAuth token: %v", err)
		httpError(w, http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(w, "OK")
}
