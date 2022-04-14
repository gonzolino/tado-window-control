package windowcontrol

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gonzolino/gotado/v2"
)

const (
	secretTadoUsername = "tado_username"
	secretTadoPassword = "tado_password"
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
	tadoClientSecret, ok := os.LookupEnv("TADO_CLIENT_SECRET")
	if !ok {
		log.Println("Missing environment variable 'TADO_CLIENT_SECRET'")
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

	tadoUsername, err := secretmanager.AccessSecret(ctx, projectID, secretTadoUsername)
	if err != nil {
		log.Printf("Failed to get tado username: %v", err)
		httpError(w, http.StatusInternalServerError)
		return
	}
	tadoPassword, err := secretmanager.AccessSecret(ctx, projectID, secretTadoPassword)
	if err != nil {
		log.Printf("Failed to get tado password: %v", err)
		httpError(w, http.StatusInternalServerError)
		return
	}

	// tadoClient, err := gotado.NewClient(tadoClientID, tadoClientSecret).
	// 	WithTimeout(5*time.Second).
	// 	WithCredentials(ctx, tadoUsername, tadoPassword)
	// if err != nil {
	// 	// Treat failed tado login as internal server error, since credentials,
	// 	// authentication, etc. of tado° is all managed on the server side. User has no
	// 	log.Printf("Failed tado° login: %v", err)
	// 	httpError(w, http.StatusInternalServerError)
	// 	return
	// }

	tado := gotado.New(tadoClientID, tadoClientSecret)
	user, err := tado.Me(ctx, tadoUsername, tadoPassword)
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
