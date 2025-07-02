package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"myiradat-backend-auth/internal/config"
)

type IJwtTokenGenerator interface {
	GenerateAccessToken(email string, roles []TokenServiceRole) (string, error)
	GenerateRefreshToken(email string) (string, error)
	ParseRefreshToken(tokenStr string) (*RefreshTokenClaims, error)
	ParseAccessToken(tokenStr string) (*AccessTokenClaims, error)
}

type jwtGenerator struct {
	config *config.JWTConfig
}

func NewJWTGenerator(cfg *config.JWTConfig) IJwtTokenGenerator {
	return &jwtGenerator{
		config: cfg,
	}
}

func (j *jwtGenerator) GenerateAccessToken(email string, roles []TokenServiceRole) (string, error) {
	claims := jwt.MapClaims{
		"email":    email,
		"services": roles,
		"exp":      time.Now().Add(j.config.AccessTokenExp).Unix(),
		"iat":      time.Now().Unix(),
		"iss":      "myiradat-auth",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(j.config.Secret))
}

func (j *jwtGenerator) GenerateRefreshToken(email string) (string, error) {
	claims := jwt.MapClaims{
		"email": email,
		"exp":   time.Now().Add(j.config.RefreshTokenExp).Unix(),
		"iat":   time.Now().Unix(),
		"iss":   j.config.Issuer,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(j.config.Secret))
}

func (j *jwtGenerator) ParseRefreshToken(tokenStr string) (*RefreshTokenClaims, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(j.config.Secret), nil
	})

	if err != nil || !token.Valid {
		return nil, errors.New("invalid or expired refresh token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("cannot parse claims")
	}

	email, ok := claims["email"].(string)
	if !ok {
		return nil, errors.New("email not found in token")
	}

	return &RefreshTokenClaims{Email: email}, nil
}

func (j *jwtGenerator) ParseAccessToken(tokenStr string) (*AccessTokenClaims, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(j.config.Secret), nil
	})
	if err != nil || !token.Valid {
		return nil, errors.New("invalid or expired token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	email := fmt.Sprintf("%v", claims["email"])

	// 💥 THE FIX IS HERE:
	var services []TokenServiceRole

	// Safely re-marshal and unmarshal
	if rawServices, ok := claims["services"]; ok {
		// Marshal the rawServices back to JSON
		jsonData, err := json.Marshal(rawServices)
		if err != nil {
			return nil, err
		}

		// Unmarshal into our struct
		if err := json.Unmarshal(jsonData, &services); err != nil {
			return nil, err
		}
	}

	return &AccessTokenClaims{
		Email:    email,
		Services: services,
	}, nil
}
