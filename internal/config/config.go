package config

import (
	"log"
	"myiradat-backend-auth/internal/middleware/auth"
	"os"

	"github.com/joho/godotenv"
)

func LoadEnv() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}
}

func InitAuth() auth.IJwtTokenGenerator {
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET is not set in environment variables")
	}
	return auth.NewJWTGenerator(jwtSecret)
}
