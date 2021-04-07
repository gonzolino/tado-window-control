package windowcontrol

import (
	"context"
	"encoding/json"
	"fmt"
)

const (
	secretAuthTokens = "auth_tokens"
)

func isValidToken(ctx context.Context, secretmanager *SecretManager, projectID, token string) (bool, error) {
	tokenStr, err := secretmanager.AccessSecret(ctx, projectID, secretAuthTokens)
	if err != nil {
		return false, fmt.Errorf("Can't check authentication token: %v", err)
	}

	var tokens []string
	if err := json.Unmarshal([]byte(tokenStr), &tokens); err != nil {
		return false, fmt.Errorf("Secret '%s' must be valid json: %v", secretAuthTokens, err)
	}

	for _, t := range tokens {
		if token == t {
			return true, nil
		}
	}
	return false, nil
}
