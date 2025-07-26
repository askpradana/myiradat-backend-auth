package middleware

import (
	"myiradat-backend-auth/internal/configs"
	"myiradat-backend-auth/internal/response"
	"strings"

	"github.com/gin-gonic/gin"
)

// Middleware for verifying access token and extracting email from it
func AuthMiddleware(role string) gin.HandlerFunc {
	jwtGen := NewJWTGenerator(configs.InitJWTConfig())

	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			response.Error(c, "Authorization header required")
			c.Abort()
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == authHeader {
			response.Error(c, "Bearer token malformed")
			c.Abort()
			return
		}

		claims, err := jwtGen.ParseAccessToken(token)
		if err != nil {
			response.Error(c, "Invalid or expired token: "+err.Error())
			c.Abort()
			return
		}

		c.Set("email", claims.Email)
		c.Set("services", claims.Services)
		c.Next()
	}
}
