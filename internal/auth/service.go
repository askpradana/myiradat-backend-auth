package auth

import (
	"fmt"
	authmiddleware "myiradat-backend-auth/internal/middleware/auth"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Service interface {
	Register(input RegisterRequest) (RegisterResponse, map[string]string, error)
	Login(input LoginRequest) (LoginResponse, map[string]string, error)
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

func (s *service) Login(input LoginRequest) (LoginResponse, map[string]string, error) {
	errs := make(map[string]string)

	// 1. Find user
	var user Profile
	if err := s.repo.FindProfileByEmail(&user, input.Email); err != nil {
		errs["email"] = "email not found"
		return LoginResponse{}, errs, nil
	}

	// 2. Compare passwords
	if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)) != nil {
		errs["password"] = "invalid password"
		return LoginResponse{}, errs, nil
	}

	// 3. Get roles & services
	roles, err := s.repo.FindRolesByProfileID(user.ID)
	if err != nil {
		return LoginResponse{}, nil, err
	}

	tokenRoles := make([]authmiddleware.TokenServiceRole, len(roles))
	for i, r := range roles {
		tokenRoles[i] = authmiddleware.TokenServiceRole{
			ServiceName: r.ServiceName,
			RoleName:    r.RoleName,
		}
	}

	// 4. Build access token
	token, err := authmiddleware.GenerateJWT(user.Email, tokenRoles)
	if err != nil {
		return LoginResponse{}, nil, err
	}

	refresh, err := authmiddleware.GenerateRefreshToken(user.Email)
	if err != nil {
		return LoginResponse{}, nil, err
	}

	return LoginResponse{
		AccessToken:  token,
		RefreshToken: refresh,
	}, nil, nil
}
