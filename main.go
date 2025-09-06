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

	_ "github.com/lib/pq"

	"github.com/joho/godotenv"
	"github.com/quduss/Chirpy/internal/database"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
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
	cfg.fileserverHits.Store(0)
	w.WriteHeader(http.StatusOK)
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Write the Content-Type header
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	// 2. Write the status code using w.WriteHeader
	w.WriteHeader(http.StatusOK) // 200 OK

	// 3. Write the body text using w.Write
	w.Write([]byte("OK"))
}

func validateChirpHandler(w http.ResponseWriter, r *http.Request) {
	// Set content type
	w.Header().Set("Content-Type", "application/json")

	// Check if method is POST
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Method not allowed"})
		return
	}

	// Decode JSON request body
	var req ValidateChirpRequest
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid JSON"})
		return
	}

	// Validate chirp body
	chirpBody := strings.TrimSpace(req.Body)

	// Check if chirp is empty
	if len(chirpBody) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Chirp cannot be empty"})
		return
	}

	// Check if chirp is too long (more than 140 characters)
	if len(chirpBody) > 140 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Chirp is too long"})
		return
	}

	// Clean profane words from the chirp
	cleanedBody := cleanProfanity(chirpBody)

	// If we get here, the chirp is valid
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(CleanedResponse{CleanedBody: cleanedBody})
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

func main() {
	err := godotenv.Load()

	if err != nil {
		log.Fatal("Error loading .env file")
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
	mux := http.NewServeMux()

	// Add the readiness endpoint at /healthz
	mux.HandleFunc("GET /api/healthz", healthzHandler)

	// Strip the /app prefix before passing to the fileserver
	fsHandler := http.StripPrefix("/app", http.FileServer(http.Dir(".")))

	mux.Handle("/app/", apiCfg.middlewareMetricsInc(fsHandler))

	mux.HandleFunc("GET /admin/metrics", apiCfg.handlerMetrics)

	mux.HandleFunc("POST /admin/reset", apiCfg.handlerReset)

	mux.HandleFunc("/api/validate_chirp", validateChirpHandler)

	server := &http.Server{
		Handler: mux,
		Addr:    ":8080",
	}

	server.ListenAndServe()
}
