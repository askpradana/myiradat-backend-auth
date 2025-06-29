package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type IJwtTokenGenerator interface {
	GenerateAccessToken(email string, roles []TokenServiceRole) (string, error)
	GenerateRefreshToken(email string) (string, error)
	ParseRefreshToken(tokenStr string) (*RefreshTokenClaims, error)
}
type jwtGenerator struct {
	secret []byte
}

func NewJWTGenerator(secret string) IJwtTokenGenerator {
	return &jwtGenerator{
		secret: []byte(secret),
	}
}

func (j *jwtGenerator) GenerateAccessToken(email string, roles []TokenServiceRole) (string, error) {
	claims := jwt.MapClaims{
		"email":    email,
		"services": roles,
		"exp":      time.Now().Add(1 * time.Hour).Unix(),
		"iat":      time.Now().Unix(),
		"iss":      "myiradat-auth",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.secret)
}

func (j *jwtGenerator) GenerateRefreshToken(email string) (string, error) {
	claims := jwt.MapClaims{
		"email": email,
		"exp":   time.Now().Add(7 * 24 * time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"iss":   "myiradat-auth",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.secret)
}

func (j *jwtGenerator) ParseRefreshToken(tokenStr string) (*RefreshTokenClaims, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return j.secret, nil
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

	return &RefreshTokenClaims{
		Email: email,
	}, nil
}
