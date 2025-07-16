package main

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"myiradat-backend-auth/internal/auth"
	"myiradat-backend-auth/internal/config"
	"myiradat-backend-auth/internal/database"
	authMiddleware "myiradat-backend-auth/internal/middleware/auth"
	"myiradat-backend-auth/internal/validation"
	"time"
)

func main() {
	config.LoadEnv()
	database.InitDB()
	validation.InitValidator()

	jwtConfig := config.InitJWTConfig()

	jwtGenerator := authMiddleware.NewJWTGenerator(jwtConfig)

	r := gin.Default()

	authRepo := auth.NewRepository(database.DB)
	authService := auth.NewService(authRepo, jwtGenerator)
	authHandler := auth.NewHandler(authService, jwtGenerator)

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Authorization", "Content-Type"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	authGroup := r.Group("/auth")
	{
		authGroup.POST("/register", authHandler.Register)
		authGroup.POST("/login", authHandler.Login)
		authGroup.POST("/refresh-token", authHandler.RefreshToken)
		authGroup.POST("/change-password", authHandler.ChangePassword)
		authGroup.POST("/logout", authHandler.Logout)
		authGroup.GET("/service-roles", authHandler.GetServiceRoles)
		authGroup.GET("/me", authHandler.GetMe)

		//untuk keperluan testing jangan di expose ke luar
		//authGroup.POST("/validate-token", authHandler.ValidateToken)
	}

	r.Run()
}
