package main

import (
	"encoding/json"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Set JSON content type
		w.Header().Set("Content-Type", "application/json")

		// Create a simple response
		resp := map[string]string{
			"status": "auth service is running",
		}

		// Encode the response as JSON
		json.NewEncoder(w).Encode(resp)
	})

	// Start the server on port 8080
	if err := http.ListenAndServe(":7791", nil); err != nil {
		panic(err)
	}
}
