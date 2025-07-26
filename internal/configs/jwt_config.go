package configs

import (
	"time"
)

type JWTConfig struct {
	Secret          string
	Issuer          string
	AccessTokenExp  time.Duration
	RefreshTokenExp time.Duration
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
