package main

import (
	"github.com/gin-gonic/gin"
	"myiradat-backend-auth/internal/auth"
	"myiradat-backend-auth/internal/config"
	"myiradat-backend-auth/internal/database"
	"myiradat-backend-auth/internal/validation"
)

func main() {
	config.LoadEnv()
	database.InitDB()
	validation.InitValidator()

	r := gin.Default()

	// Auth DI
	authRepo := auth.NewRepository(database.DB)
	authService := auth.NewService(authRepo)
	authHandler := auth.NewHandler(authService)

	r.POST("/auth/register", authHandler.Register)
	r.POST("/auth/login", authHandler.Login)

	r.Run()
}
