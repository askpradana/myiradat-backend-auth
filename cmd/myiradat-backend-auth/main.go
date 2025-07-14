package main

import (
	"myiradat-backend-auth/internal/auth"
	"myiradat-backend-auth/internal/config"
	"myiradat-backend-auth/internal/database"
	authMiddleware "myiradat-backend-auth/internal/middleware/auth"
	"myiradat-backend-auth/internal/routes"
	"myiradat-backend-auth/internal/validation"
)

func main() {
	config.LoadEnv()
	database.InitDB()
	validation.InitValidator()

	jwtConfig := config.InitJWTConfig()
	jwtGenerator := authMiddleware.NewJWTGenerator(jwtConfig)

	// Initialize dependencies
	authRepo := auth.NewRepository(database.DB)
	authService := auth.NewService(authRepo, jwtGenerator)
	authHandler := auth.NewHandler(authService, jwtGenerator)

	// Setup routes
	r := routes.SetupRoutes(authHandler)

	// Start server
	port := jwtConfig.ApplicationPort
	if port == "" {
		port = "8080"
	}

	r.Run("0.0.0.0:" + port)
}
