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
	// Initialize an empty field error map
	fieldErrors := make(map[string]string)

	// Step 1: Check if email already exists
	if s.repo.IsEmailExist(input.Email) {
		fieldErrors["email"] = "email already exists"
		return RegisterResponse{}, fieldErrors, nil
	}

	// Step 2: Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return RegisterResponse{}, nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Step 3: Build profile model
	profile := Profile{
		Name:       input.Name,
		Email:      input.Email,
		NoHP:       input.NoHP,
		Password:   string(hashedPassword),
		CreatedAt:  time.Now(),
		CreatedBy:  "system", // optionally extract user if logged-in
		ModifiedAt: time.Now(),
		ModifiedBy: "system",
	}

	// Step 4: Save profile + service-role relation
	err = s.repo.CreateProfileWithRoles(&profile, input.Services)
	if err != nil {
		if err.Error() == "invalid service and roles" {
			fieldErrors["services"] = "invalid service and role mapping"
			return RegisterResponse{}, fieldErrors, nil
		}
		return RegisterResponse{}, nil, fmt.Errorf("failed to create profile: %w", err)
	}

	// Step 5: Return success response
	return RegisterResponse{
		ID:    profile.ID,
		Email: profile.Email,
	}, nil, nil
}
