package auth

import (
	"errors"
	"net/http"
	"strings"
)

// GetAPIKey extracts the API key from the Authorization header
// Expected format: "ApiKey THE_KEY_HERE"
func GetAPIKey(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("no authorization header found")
	}
	// Split the header into parts
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 {
		return "", errors.New("malformed authorization header")
	}

	// Check if the first part is "ApiKey"
	if parts[0] != "ApiKey" {
		return "", errors.New("authorization header must start with 'ApiKey'")
	}

	// Return the API key (second part)
	apiKey := strings.TrimSpace(parts[1])
	if apiKey == "" {
		return "", errors.New("api key is empty")
	}

	return apiKey, nil
}
