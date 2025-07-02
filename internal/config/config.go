package config

import (
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"
)

type JWTConfig struct {
	Secret          string
	Issuer          string
	AccessTokenExp  time.Duration
	RefreshTokenExp time.Duration
}

func LoadEnv() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}
}

func InitJWTConfig() *JWTConfig {
	LoadEnv()

	return &JWTConfig{
		Secret:          getEnv("JWT_SECRET", ""),
		Issuer:          getEnv("JWT_ISSUER", "myiradat-auth"),
		AccessTokenExp:  getEnvAsDuration("JWT_ACCESS_EXP", 1*time.Hour),
		RefreshTokenExp: getEnvAsDuration("JWT_REFRESH_EXP", 168*time.Hour),
	}
}

// Helper functions
func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	if value, exists := os.LookupEnv(key); exists {
		if dur, err := time.ParseDuration(value); err == nil {
			return dur
		}
	}
	return defaultValue
}
