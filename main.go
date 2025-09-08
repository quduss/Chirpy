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
	"github.com/quduss/Chirpy/internal/database"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	platform       string
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
}

// CreateUserRequest represents the request body for creating a user
type CreateUserRequest struct {
	Email string `json:"email"`
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
	// Create user in database
	dbUser, err := cfg.db.CreateUser(r.Context(), req.Email)
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
	if len(body) > maxChirpLength {
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

func main() {
	err := godotenv.Load()

	if err != nil {
		log.Fatal("Error loading .env file")
	}

	platform := os.Getenv("PLATFORM")
	if platform == "" {
		platform = "prod" // Default to the SAFER option
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

	server := &http.Server{
		Handler: mux,
		Addr:    ":8080",
	}

	server.ListenAndServe()
}
