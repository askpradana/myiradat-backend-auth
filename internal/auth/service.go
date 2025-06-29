package auth

import (
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Service interface {
	Register(input RegisterRequest) (RegisterResponse, map[string]string, error)
}

type service struct {
	repo Repository
}

func NewService(r Repository) Service {
	return &service{repo: r}
}

func (s *service) Register(input RegisterRequest) (RegisterResponse, map[string]string, error) {

	// Check if email exists
	if s.repo.IsEmailExist(input.Email) {
		return RegisterResponse{}, map[string]string{
			"email": "email already exists",
		}, nil
	}

	// Create profile
	hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return RegisterResponse{}, nil, fmt.Errorf("password hashing failed: %w", err)
	}

	profile := Profile{
		Email:      input.Email,
		Password:   string(hash),
		CreatedAt:  time.Now(),
		CreatedBy:  "system",
		ModifiedAt: time.Now(),
		ModifiedBy: "system",
	}

	// Save to database
	if err := s.repo.CreateProfileWithRoles(&profile, input.Services); err != nil {
		if err.Error() == "invalid service and roles" {
			return RegisterResponse{}, map[string]string{
				"services": err.Error(),
			}, nil
		}
		return RegisterResponse{}, nil, err
	}

	return RegisterResponse{
		ID:    profile.ID,
		Email: profile.Email,
	}, nil, nil
}
