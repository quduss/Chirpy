package main

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

type apiConfig struct {
	fileserverHits atomic.Int32
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

// handlerMetrics returns the current hit count as plain text
func (cfg *apiConfig) handlerMetrics(w http.ResponseWriter, r *http.Request) {
	hits := cfg.fileserverHits.Load()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "Hits: %d", hits)
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

func main() {
	apiCfg := &apiConfig{}

	mux := http.NewServeMux()

	// Add the readiness endpoint at /healthz
	mux.HandleFunc("/healthz", healthzHandler)

	// Strip the /app prefix before passing to the fileserver
	fsHandler := http.StripPrefix("/app", http.FileServer(http.Dir(".")))

	mux.Handle("/app/", apiCfg.middlewareMetricsInc(fsHandler))

	mux.HandleFunc("/metrics", apiCfg.handlerMetrics)

	mux.HandleFunc("/reset", apiCfg.handlerReset)

	server := &http.Server{
		Handler: mux,
		Addr:    ":8080",
	}

	server.ListenAndServe()
}
