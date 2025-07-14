package routes

import (
	"myiradat-backend-auth/internal/auth"
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// SetupRoutes configures all routes and middleware for the application
func SetupRoutes(authHandler *auth.Handler) *gin.Engine {
	r := gin.Default()

	// CORS configuration
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"}, // ! Only used in DEV
		AllowMethods:     []string{"GET", "POST", "PUT", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Health check endpoint
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Auth Service is running in docker!"})
	})

	// Auth routes
	setupAuthRoutes(r, authHandler)

	return r
}

// setupAuthRoutes configures all authentication-related routes
func setupAuthRoutes(r *gin.Engine, authHandler *auth.Handler) {
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
}
