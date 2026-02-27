package windowcontrol

import (
	"context"
	"fmt"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SecretManager allows to access secrets
type SecretManager struct {
	client *secretmanager.Client
}

// NewSecretManager creates a new SecretManager object
func NewSecretManager(ctx context.Context) (*SecretManager, error) {
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to create secretmanager client: %w", err)
	}
	return &SecretManager{
		client: client,
	}, nil
}

// AccessSecret requests and returns a secret with the given name in the given project
func (sm *SecretManager) AccessSecret(ctx context.Context, projectID, secretName string) (string, error) {
	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("projects/%s/secrets/%s/versions/latest", projectID, secretName),
	}
	result, err := sm.client.AccessSecretVersion(ctx, req)
	if err != nil {
		return "", fmt.Errorf("unable to access secret %s in project %s: %w", secretName, projectID, err)
	}
	return string(result.Payload.Data), nil
}

// AddSecretVersion adds a new version of the given secret with the provided data.
// If a previous version exists, it will be destroyed after the new version is added.
func (sm *SecretManager) AddSecretVersion(ctx context.Context, projectID, secretName string, data []byte) error {
	secretPath := fmt.Sprintf("projects/%s/secrets/%s", projectID, secretName)

	// Get the current latest version name before adding the new one
	prevVersion, err := sm.client.GetSecretVersion(ctx, &secretmanagerpb.GetSecretVersionRequest{
		Name: secretPath + "/versions/latest",
	})
	if err != nil {
		if status.Code(err) != codes.NotFound {
			return fmt.Errorf("unable to get latest secret version for %s in project %s: %w", secretName, projectID, err)
		}
		prevVersion = nil
	}

	// Add the new secret version
	_, err = sm.client.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{
		Parent: secretPath,
		Payload: &secretmanagerpb.SecretPayload{
			Data: data,
		},
	})
	if err != nil {
		return fmt.Errorf("unable to add secret version for %s in project %s: %w", secretName, projectID, err)
	}

	// Destroy the previous version
	if prevVersion != nil {
		_, err = sm.client.DestroySecretVersion(ctx, &secretmanagerpb.DestroySecretVersionRequest{
			Name: prevVersion.Name,
		})
		if err != nil {
			return fmt.Errorf("unable to destroy previous secret version %s: %w", prevVersion.Name, err)
		}
	}

	return nil
}
