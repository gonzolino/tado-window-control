package windowcontrol

import (
	"context"
	"fmt"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
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

// AddSecretVersion adds a new version of the given secret with the provided data
func (sm *SecretManager) AddSecretVersion(ctx context.Context, projectID, secretName string, data []byte) error {
	req := &secretmanagerpb.AddSecretVersionRequest{
		Parent: fmt.Sprintf("projects/%s/secrets/%s", projectID, secretName),
		Payload: &secretmanagerpb.SecretPayload{
			Data: data,
		},
	}
	_, err := sm.client.AddSecretVersion(ctx, req)
	if err != nil {
		return fmt.Errorf("unable to add secret version for %s in project %s: %w", secretName, projectID, err)
	}
	return nil
}
