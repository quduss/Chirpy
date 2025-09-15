package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestHashPassword(t *testing.T) {
	password := "testpassword123"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	if hash == "" {
		t.Fatal("Hash should not be empty")
	}

	if hash == password {
		t.Fatal("Hash should not equal the original password")
	}
}

func TestCheckPasswordHash(t *testing.T) {
	password := "testpassword123"
	wrongPassword := "wrongpassword"

	// Hash the password
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	// Test correct password
	err = CheckPasswordHash(password, hash)
	if err != nil {
		t.Fatalf("Password validation should pass for correct password: %v", err)
	}

	// Test wrong password
	err = CheckPasswordHash(wrongPassword, hash)
	if err == nil {
		t.Fatal("Password validation should fail for wrong password")
	}
}

func TestHashPasswordDifferentOutputs(t *testing.T) {
	password := "testpassword123"

	hash1, err := HashPassword(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	hash2, err := HashPassword(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	// Bcrypt should produce different hashes for the same password due to salt
	if hash1 == hash2 {
		t.Fatal("Bcrypt should produce different hashes for the same password")
	}

	// But both should validate correctly
	if err := CheckPasswordHash(password, hash1); err != nil {
		t.Fatalf("First hash should validate correctly: %v", err)
	}

	if err := CheckPasswordHash(password, hash2); err != nil {
		t.Fatalf("Second hash should validate correctly: %v", err)
	}
}

func TestMakeJWT(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "test-secret-key"
	expiresIn := time.Hour

	tokenString, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("Failed to create JWT: %v", err)
	}

	if tokenString == "" {
		t.Fatal("JWT token should not be empty")
	}

	// Validate the created token
	parsedUserID, err := ValidateJWT(tokenString, tokenSecret)
	if err != nil {
		t.Fatalf("Failed to validate JWT: %v", err)
	}

	if parsedUserID != userID {
		t.Fatalf("Expected user ID %v, got %v", userID, parsedUserID)
	}
}

func TestValidateJWT(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "test-secret-key"
	expiresIn := time.Hour

	// Create a valid token
	tokenString, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("Failed to create JWT: %v", err)
	}

	// Test valid token
	parsedUserID, err := ValidateJWT(tokenString, tokenSecret)
	if err != nil {
		t.Fatalf("Failed to validate valid JWT: %v", err)
	}

	if parsedUserID != userID {
		t.Fatalf("Expected user ID %v, got %v", userID, parsedUserID)
	}
}

func TestValidateJWTWithWrongSecret(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "test-secret-key"
	wrongSecret := "wrong-secret-key"
	expiresIn := time.Hour

	// Create a token with correct secret
	tokenString, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("Failed to create JWT: %v", err)
	}

	// Try to validate with wrong secret
	_, err = ValidateJWT(tokenString, wrongSecret)
	if err == nil {
		t.Fatal("JWT validation should fail with wrong secret")
	}
}

func TestValidateJWTExpired(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "test-secret-key"
	expiresIn := time.Millisecond // Very short expiration

	// Create a token that will expire quickly
	tokenString, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("Failed to create JWT: %v", err)
	}

	// Wait for token to expire
	time.Sleep(time.Millisecond * 10)

	// Try to validate expired token
	_, err = ValidateJWT(tokenString, tokenSecret)
	if err == nil {
		t.Fatal("JWT validation should fail for expired token")
	}
}

func TestValidateJWTInvalidToken(t *testing.T) {
	tokenSecret := "test-secret-key"
	invalidToken := "invalid.jwt.token"

	// Try to validate invalid token
	_, err := ValidateJWT(invalidToken, tokenSecret)
	if err == nil {
		t.Fatal("JWT validation should fail for invalid token")
	}
}

func TestMakeJWTDifferentUserIDs(t *testing.T) {
	userID1 := uuid.New()
	userID2 := uuid.New()
	tokenSecret := "test-secret-key"
	expiresIn := time.Hour

	// Create tokens for different users
	token1, err := MakeJWT(userID1, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("Failed to create JWT for user 1: %v", err)
	}

	token2, err := MakeJWT(userID2, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("Failed to create JWT for user 2: %v", err)
	}

	// Tokens should be different
	if token1 == token2 {
		t.Fatal("JWT tokens for different users should be different")
	}

	// Validate each token returns correct user ID
	parsedUserID1, err := ValidateJWT(token1, tokenSecret)
	if err != nil {
		t.Fatalf("Failed to validate JWT for user 1: %v", err)
	}

	parsedUserID2, err := ValidateJWT(token2, tokenSecret)
	if err != nil {
		t.Fatalf("Failed to validate JWT for user 2: %v", err)
	}

	if parsedUserID1 != userID1 {
		t.Fatalf("Expected user ID %v for token 1, got %v", userID1, parsedUserID1)
	}

	if parsedUserID2 != userID2 {
		t.Fatalf("Expected user ID %v for token 2, got %v", userID2, parsedUserID2)
	}
}
