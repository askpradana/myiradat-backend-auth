// @title Iradat Auth Service API
// @version 1.0
// @description This is the User Service API for Iradat project.
// @host localhost:8000
// @BasePath /

package main

import (
	"log"
	"myiradat-backend-auth/internal/auth"
	// "myiradat-backend-auth/docs"
	"myiradat-backend-auth/internal/configs"
	"os"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	configs.LoadEnv()

	// Load configurations
	configs.ReloadDatabaseConfig()
	// config.ReloadRedis()

	// Get HTTP port
	httpPort := os.Getenv("PORT")
	if httpPort == "" {
		httpPort = "8001"
	}

	// docs.SetupSwagger(httpPort)

	router := gin.Default()

	// Add CORS middleware to allow all origins
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	auth.HttpHandler(router)

	// router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	log.Printf("✅ Starting HTTP server on port %s (ENV=%s)\n", httpPort, os.Getenv("ENV"))
	if err := router.Run(":" + httpPort); err != nil {
		log.Fatalf("❌ Server failed to start: %v", err)
	}
}
