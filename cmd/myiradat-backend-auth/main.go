package main

import (
	"github.com/gin-gonic/gin"
	"myiradat-backend-auth/internal/auth"
	"myiradat-backend-auth/internal/config"
	"myiradat-backend-auth/internal/database"
	authMiddleware "myiradat-backend-auth/internal/middleware/auth"
	"myiradat-backend-auth/internal/validation"
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

	authGroup := r.Group("/auth")
	{
		authGroup.POST("/register", authHandler.Register)
		authGroup.POST("/login", authHandler.Login)
		authGroup.POST("/refresh-token", authHandler.RefreshToken)
		authGroup.POST("/change-password", authHandler.ChangePassword)
		authGroup.POST("/logout", authHandler.Logout)

		//untuk keperluan testing jangan di expose ke luar
		//authGroup.POST("/validate-token", authHandler.ValidateToken)
	}

	r.Run()
}
