package main

import (
	"encoding/json"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Enable CORS
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")

		// Create a simple response
		resp := map[string]string{
			"status": "auth service is running",
		}

		// Encode the response as JSON
		json.NewEncoder(w).Encode(resp)
	})

	port := ":7791"
	log.Printf("Auth service is running on port %s\n", port)

	// Start the server
	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
