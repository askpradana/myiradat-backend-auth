package main

import (
	"encoding/json"
	"log"
	"net/http"
)

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Enable CORS
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")

		// Create a simple response
		resp := map[string]string{
			"status": "auth service is running and auto deploy success with docker!",
		}

		// Encode the response as JSON
		json.NewEncoder(w).Encode(resp)
	})

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		// Enable CORS
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		if r.Method != http.MethodPost {
			http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
			return
		}

		var req LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Mock credentials
		if req.Email == "mail@mail.com" && req.Password == "password" {
			resp := map[string]string{
				"status":  "success",
				"message": "Login successful",
			}
			json.NewEncoder(w).Encode(resp)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			resp := map[string]string{
				"status":  "error",
				"message": "Invalid credentials",
			}
			json.NewEncoder(w).Encode(resp)
		}
	})

	port := ":7791"
	log.Printf("Auth service is running on port %s\n", port)

	// Start the server
	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
