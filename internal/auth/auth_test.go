package auth

import (
	"testing"
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
