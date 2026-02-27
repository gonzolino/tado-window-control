package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/gonzolino/gotado/v2"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
)

const secretTadoOAuthToken = "tado_oauth_token"

func main() {
	clientID := os.Getenv("TADO_CLIENT_ID")
	if clientID == "" {
		fmt.Fprintln(os.Stderr, "TADO_CLIENT_ID environment variable is required")
		os.Exit(1)
	}
	projectID := os.Getenv("GCP_PROJECT")
	if projectID == "" {
		fmt.Fprintln(os.Stderr, "GCP_PROJECT environment variable is required")
		os.Exit(1)
	}

	ctx := context.Background()

	// Start device authorization flow
	config := gotado.AuthConfig(clientID, "offline_access")
	response, err := config.DeviceAuth(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start device authorization: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("To authenticate, visit: %s\n", response.VerificationURIComplete)
	fmt.Println("Waiting for authorization...")

	// Wait for user to authorize
	token, err := config.DeviceAccessToken(ctx, response)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to obtain access token: %v\n", err)
		os.Exit(1)
	}

	// Store token in Secret Manager
	tokenJSON, err := json.Marshal(token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to serialize token: %v\n", err)
		os.Exit(1)
	}

	smClient, err := secretmanager.NewClient(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create Secret Manager client: %v\n", err)
		os.Exit(1)
	}
	defer smClient.Close()

	_, err = smClient.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{
		Parent: fmt.Sprintf("projects/%s/secrets/%s", projectID, secretTadoOAuthToken),
		Payload: &secretmanagerpb.SecretPayload{
			Data: tokenJSON,
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to store token in Secret Manager: %v\n", err)
		fmt.Fprintln(os.Stderr, "Token JSON (save manually):")
		fmt.Fprintln(os.Stderr, string(tokenJSON))
		os.Exit(1)
	}

	fmt.Println("OAuth token stored successfully in Secret Manager.")
}
