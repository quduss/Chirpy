package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/joho/godotenv"
	"github.com/quduss/Chirpy/internal/auth"
	"github.com/quduss/Chirpy/internal/database"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	platform       string
	jwtSecret      string
}

type ValidateChirpRequest struct {
	Body string `json:"body"`
}

// Error response structure
type ErrorResponse struct {
	Error string `json:"error"`
}

// Success response structure
type ValidResponse struct {
	Valid bool `json:"valid"`
}

// Success response structure
type CleanedResponse struct {
	CleanedBody string `json:"cleaned_body"`
}

// User represents the user response structure
type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
	Token     string    `json:"token"`
}

// CreateUserRequest represents the request body for creating a user
type CreateUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Email            string `json:"email"`
	Password         string `json:"password"`
	ExpiresInSeconds *int   `json:"expires_in_seconds,omitempty"`
}

// CreateChirpRequest represents the request body for creating a chirp
type CreateChirpRequest struct {
	Body   string    `json:"body"`
	UserID uuid.UUID `json:"user_id"`
}

type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

// handlerMetrics returns the current hit count as plain text
func (cfg *apiConfig) handlerMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	hits := cfg.fileserverHits.Load()

	// Create the HTML response using the template
	htmlTemplate := `<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`

	// Use fmt.Sprintf to insert the hit count
	htmlResponse := fmt.Sprintf(htmlTemplate, hits)

	// Write the HTML response
	w.Write([]byte(htmlResponse))
}

// handlerReset resets the hit counter back to 0
func (cfg *apiConfig) handlerReset(w http.ResponseWriter, r *http.Request) {
	// Check if platform is dev
	if cfg.platform != "dev" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	cfg.fileserverHits.Store(0)
	// Delete all users from database
	err := cfg.db.DeleteAllUsers(r.Context())
	if err != nil {
		log.Printf("Error deleting users: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Set response headers
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hits reset to 0 and database cleared"))
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Write the Content-Type header
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	// 2. Write the status code using w.WriteHeader
	w.WriteHeader(http.StatusOK) // 200 OK

	// 3. Write the body text using w.Write
	w.Write([]byte("OK"))
}

// cleanProfanity replaces profane words with ****
func cleanProfanity(text string) string {
	// List of profane words to replace
	profaneWords := []string{"kerfuffle", "sharbert", "fornax"}

	// Split text into words
	words := strings.Fields(text)

	// Check each word and replace if it matches a profane word
	for i, word := range words {
		// Convert to lowercase for comparison (case-insensitive)
		lowerWord := strings.ToLower(word)

		// Check against each profane word
		for _, profane := range profaneWords {
			if lowerWord == profane {
				words[i] = "****"
				break
			}
		}
	}

	// Join words back together with spaces
	return strings.Join(words, " ")
}

// createUserHandler handles POST /api/users
func (cfg *apiConfig) createUserHandler(w http.ResponseWriter, r *http.Request) {
	// Decode JSON request body
	var req CreateUserRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	// Validate email is not empty
	if req.Email == "" {
		http.Error(w, "Email is required", http.StatusBadRequest)
		return
	}

	if req.Password == "" {
		http.Error(w, "Password is required", http.StatusBadRequest)
		return
	}

	// Hash the password
	hashedPassword, err := auth.HashPassword(req.Password)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}
	// Create user in database
	dbUser, err := cfg.db.CreateUser(r.Context(), database.CreateUserParams{
		Email:          req.Email,
		HashedPassword: hashedPassword,
	})

	if err != nil {
		log.Printf("Error creating user: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	// Convert database user to response user
	user := User{
		ID:        dbUser.ID,
		CreatedAt: dbUser.CreatedAt,
		UpdatedAt: dbUser.UpdatedAt,
		Email:     dbUser.Email,
	}
	// Set response headers
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	// Encode and send response
	if err := json.NewEncoder(w).Encode(user); err != nil {
		log.Printf("Error encoding response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// validateChirp validates and cleans the chirp body
func validateChirp(body string) (string, error) {
	const maxChirpLength = 140

	// Check if body is empty
	if strings.TrimSpace(body) == "" {
		return "", fmt.Errorf("Chirp body cannot be empty")
	}

	// Check length
	if len(strings.TrimSpace(body)) > maxChirpLength {
		return "", fmt.Errorf("Chirp is too long")
	}

	// Clean profanity
	cleanedBody := cleanProfanity(body)
	return cleanedBody, nil
}

// createChirpHandler handles POST /api/chirps
func (cfg *apiConfig) createChirpHandler(w http.ResponseWriter, r *http.Request) {
	// Decode JSON request body
	var req CreateChirpRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	// Validate chirp body
	cleanedBody, err := validateChirp(req.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Create chirp in database
	dbChirp, err := cfg.db.CreateChirp(r.Context(), database.CreateChirpParams{
		Body:   cleanedBody,
		UserID: req.UserID,
	})
	if err != nil {
		log.Printf("Error creating chirp: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	// Convert database chirp to response chirp
	chirp := Chirp{
		ID:        dbChirp.ID,
		CreatedAt: dbChirp.CreatedAt,
		UpdatedAt: dbChirp.UpdatedAt,
		Body:      dbChirp.Body,
		UserID:    dbChirp.UserID,
	}
	// Set response headers
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	// Encode and send response
	if err := json.NewEncoder(w).Encode(chirp); err != nil {
		log.Printf("Error encoding response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// getAllChirpsHandler handles GET /api/chirps
func (cfg *apiConfig) getAllChirpsHandler(w http.ResponseWriter, r *http.Request) {
	// Get all chirps from database
	dbChirps, err := cfg.db.GetAllChirps(r.Context())
	if err != nil {
		log.Printf("Error getting chirps: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Convert database chirps to response chirps
	chirps := make([]Chirp, len(dbChirps))
	for i, dbChirp := range dbChirps {
		chirps[i] = Chirp{
			ID:        dbChirp.ID,
			CreatedAt: dbChirp.CreatedAt,
			UpdatedAt: dbChirp.UpdatedAt,
			Body:      dbChirp.Body,
			UserID:    dbChirp.UserID,
		}
	}

	// Set response headers
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// Encode and send response
	if err := json.NewEncoder(w).Encode(chirps); err != nil {
		log.Printf("Error encoding response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// getChirpByIDHandler handles GET /api/chirps/{chirpID}
func (cfg *apiConfig) getChirpByIDHandler(w http.ResponseWriter, r *http.Request) {
	// Get chirp ID from path parameter
	chirpIDStr := r.PathValue("chirpID")
	if chirpIDStr == "" {
		http.Error(w, "Missing chirp ID", http.StatusBadRequest)
		return
	}
	// Parse chirp ID as UUID
	chirpID, err := uuid.Parse(chirpIDStr)
	if err != nil {
		http.Error(w, "Invalid chirp ID", http.StatusBadRequest)
		return
	}

	// Get chirp from database
	dbChirp, err := cfg.db.GetChirpByID(r.Context(), chirpID)
	if err != nil {
		// Check if it's a "no rows found" error
		if err.Error() == "sql: no rows in result set" {
			http.Error(w, "Chirp not found", http.StatusNotFound)
			return
		}
		log.Printf("Error getting chirp: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Convert database chirp to response chirp
	chirp := Chirp{
		ID:        dbChirp.ID,
		CreatedAt: dbChirp.CreatedAt,
		UpdatedAt: dbChirp.UpdatedAt,
		Body:      dbChirp.Body,
		UserID:    dbChirp.UserID,
	}

	// Set response headers
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// Encode and send response
	if err := json.NewEncoder(w).Encode(chirp); err != nil {
		log.Printf("Error encoding response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func (cfg *apiConfig) handlerLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	// Validate required fields
	if req.Email == "" || req.Password == "" {
		http.Error(w, "Incorrect email or password", http.StatusUnauthorized)
		return
	}
	// Look up user by email
	user, err := cfg.db.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		http.Error(w, "Incorrect email or password", http.StatusUnauthorized)
		return
	}

	// Check password
	if err := auth.CheckPasswordHash(req.Password, user.HashedPassword); err != nil {
		http.Error(w, "Incorrect email or password", http.StatusUnauthorized)
		return
	}
	expirationTime := time.Hour // Default 1 hour
	if req.ExpiresInSeconds != nil {
		requestedDuration := time.Duration(*req.ExpiresInSeconds) * time.Second
		// Cap at 1 hour maximum
		if requestedDuration > time.Hour {
			expirationTime = time.Hour
		} else {
			expirationTime = requestedDuration
		}
	}
	// NEW: Create JWT token
	token, err := auth.MakeJWT(user.ID, cfg.jwtSecret, expirationTime)
	if err != nil {
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		return
	}
	// Return user without password
	userResponse := User{
		ID:        user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email:     user.Email,
		Token:     token,
	}

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(userResponse); err != nil {
		log.Printf("Error encoding response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)

}

func main() {
	err := godotenv.Load()

	if err != nil {
		log.Fatal("Error loading .env file")
	}

	platform := os.Getenv("PLATFORM")
	if platform == "" {
		platform = "prod" // Default to the SAFER option
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET environment variable is required")
	}

	// Get database URL from environment
	dbURL := os.Getenv("DB_URL")
	if dbURL == "" {
		log.Fatal("DB_URL environment variable is not set")
	}
	// Open database connection
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal("Error connecting to database:", err)
	}
	defer db.Close()

	// Test the connection
	if err := db.Ping(); err != nil {
		log.Fatal("Error pinging database:", err)
	}

	// Create SQLC queries instance
	dbQueries := database.New(db)

	apiCfg := &apiConfig{}
	apiCfg.db = dbQueries
	apiCfg.platform = platform
	apiCfg.jwtSecret = jwtSecret
	mux := http.NewServeMux()

	// Add the readiness endpoint at /healthz
	mux.HandleFunc("GET /api/healthz", healthzHandler)

	// Strip the /app prefix before passing to the fileserver
	fsHandler := http.StripPrefix("/app", http.FileServer(http.Dir(".")))

	mux.Handle("/app/", apiCfg.middlewareMetricsInc(fsHandler))

	mux.HandleFunc("GET /admin/metrics", apiCfg.handlerMetrics)

	mux.HandleFunc("POST /admin/reset", apiCfg.handlerReset)

	mux.HandleFunc("POST /api/chirps", apiCfg.createChirpHandler)

	mux.HandleFunc("POST /api/users", apiCfg.createUserHandler)

	mux.HandleFunc("GET /api/chirps", apiCfg.getAllChirpsHandler)

	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirpByIDHandler)

	mux.HandleFunc("POST /api/login", apiCfg.handlerLogin)

	server := &http.Server{
		Handler: mux,
		Addr:    ":8080",
	}

	server.ListenAndServe()
}
