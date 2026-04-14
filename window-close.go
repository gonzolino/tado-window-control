package windowcontrol

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gonzolino/gotado/v2"
	"golang.org/x/oauth2"
)

// TadoWindowCloseAction holds tado° zone in which a window was closed
type TadoWindowCloseAction struct {
	HomeName string `json:"home_name"`
	ZoneName string `json:"zone_name"`
}

// CloseWindow closes the window in the given tado° zone
func CloseWindow(w http.ResponseWriter, r *http.Request) {
	var action TadoWindowCloseAction
	if err := json.NewDecoder(r.Body).Decode(&action); err != nil {
		httpError(w, http.StatusBadRequest)
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

	ctx := r.Context()

	setup := initHandler(ctx, w)
	if setup == nil {
		return
	}
	tado := gotado.NewWithTokenRefreshCallback(ctx, setup.AuthConfig, setup.OAuthToken, func(newToken *oauth2.Token) {
		if err := setup.persistToken(ctx, newToken); err != nil {
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
