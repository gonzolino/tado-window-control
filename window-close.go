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

const (
	secretTadoOAuthToken = "tado_oauth_token"
)

// TadoWindowCloseAction holds tado° zone in which a window was closed
type TadoWindowCloseAction struct {
	Token    string `json:"token"`
	HomeName string `json:"home_name"`
	ZoneName string `json:"zone_name"`
}

func httpError(w http.ResponseWriter, code int) {
	http.Error(w, http.StatusText(code), code)
}

// CloseWindow closes the window in the given tado° zone
func CloseWindow(w http.ResponseWriter, r *http.Request) {
	var action TadoWindowCloseAction
	if err := json.NewDecoder(r.Body).Decode(&action); err != nil {
		httpError(w, http.StatusBadRequest)
		return
	}
	if action.Token == "" {
		httpError(w, http.StatusForbidden)
		return
	}
	if action.HomeName == "" {
		http.Error(w, "Missing home name", http.StatusUnprocessableEntity)
		return
	}
	if action.ZoneName == "" {
		http.Error(w, "Missing zone name", http.StatusUnprocessableEntity)
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

	if ok, err := isValidToken(ctx, secretmanager, projectID, action.Token); err != nil {
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
	tado := gotado.NewWithTokenRefreshCallback(ctx, config, &token, func(newToken *oauth2.Token) {
		data, err := json.Marshal(newToken)
		if err != nil {
			log.Printf("Failed to serialize refreshed tado OAuth token: %v", err)
			return
		}
		if err := secretmanager.AddSecretVersion(ctx, projectID, secretTadoOAuthToken, data); err != nil {
			log.Printf("Failed to persist refreshed tado OAuth token: %v", err)
		}
	})
	user, err := tado.Me(ctx)
	if err != nil {
		log.Printf("Failed to get user info from tado°: %v", err)
		httpError(w, http.StatusInternalServerError)
		return
	}
	home, err := user.GetHome(ctx, action.HomeName)
	if err != nil {
		log.Printf("Failed to get home info from tado°: %v", err)
		httpError(w, http.StatusInternalServerError)
		return
	}
	zone, err := home.GetZone(ctx, action.ZoneName)
	if err != nil {
		log.Printf("Failed to get home zones from tado°: %v", err)
		httpError(w, http.StatusInternalServerError)
		return
	}

	state, err := zone.GetState(ctx)
	if err != nil {
		log.Printf("Failed to get zone state from tado°: %v", err)
		httpError(w, http.StatusInternalServerError)
		return
	}
	if state.Overlay != nil {
		// If heating was controlled manually, we assume it was controlled
		// because of an open window. We can therefore return to normal heating
		// when the window is closed.
		if state.Overlay.Type == "MANUAL" {
			if err := zone.ResumeSchedule(ctx); err != nil {
				log.Printf("Failed to resume tado° zone schedule: %v", err)
				httpError(w, http.StatusInternalServerError)
				return
			}
		}

	}

	if err := zone.CloseWindow(ctx); err != nil {
		log.Printf("Failed to close window with tado° API: %v", err)
		httpError(w, http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(w, "OK")
}
