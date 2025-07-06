package main

import (
	"myiradat-backend-auth/internal/auth"
	"myiradat-backend-auth/internal/config"
	"myiradat-backend-auth/internal/database"
	authMiddleware "myiradat-backend-auth/internal/middleware/auth"
	"myiradat-backend-auth/internal/validation"
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	config.LoadEnv()
	database.InitDB()
	validation.InitValidator()

	jwtConfig := config.InitJWTConfig()

	jwtGenerator := authMiddleware.NewJWTGenerator(jwtConfig)

	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"}, // ! Only used in DEV
		AllowMethods:     []string{"GET", "POST", "PUT", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	authRepo := auth.NewRepository(database.DB)
	authService := auth.NewService(authRepo, jwtGenerator)
	authHandler := auth.NewHandler(authService, jwtGenerator)

	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Auth Service is running in docker!"})
	})

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

	port := jwtConfig.ApplicationPort
	if port == "" {
		port = "8080"
	}

	r.Run("0.0.0.0:" + port)
}
