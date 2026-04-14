package windowcontrol

import (
	"fmt"
	"log"
	"net/http"
)

// RefreshToken refreshes the tado° OAuth token and stores the new token in Secret Manager
func RefreshToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	setup := initHandler(ctx, w)
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
