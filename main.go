package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	// Get port from environment or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Set up routes
	mux := http.NewServeMux()

	// API endpoints with CORS middleware
	mux.HandleFunc("/api/encode", CORSMiddleware(HandleEncode))
	mux.HandleFunc("/api/decode", CORSMiddleware(HandleDecode))
	mux.HandleFunc("/api/generate-keys", CORSMiddleware(HandleGenerateKeys))

	// Serve static files
	staticDir := "./static"
	fs := http.FileServer(http.Dir(staticDir))
	mux.Handle("/", fs)

	// Start server
	addr := fmt.Sprintf(":%s", port)
	log.Printf("Starting PASETO Web server on http://localhost%s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
