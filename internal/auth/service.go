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
	RefreshToken(refreshToken string) (RefreshTokenResponse, map[string]string, error)
	ChangePassword(req ChangePasswordRequest, token string) (map[string]string, error)
	ValidateToken(token string) (ValidateTokenResponse, map[string]string, error)
}

type service struct {
	repo           Repository
	authMiddleware authmiddleware.IJwtTokenGenerator
}

func NewService(r Repository, jwt authmiddleware.IJwtTokenGenerator) Service {
	return &service{
		repo:           r,
		authMiddleware: jwt,
	}
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
	token, err := s.authMiddleware.GenerateAccessToken(user.Email, tokenRoles)
	if err != nil {
		return LoginResponse{}, nil, err
	}

	refresh, err := s.authMiddleware.GenerateRefreshToken(user.Email)
	if err != nil {
		return LoginResponse{}, nil, err
	}

	return LoginResponse{
		AccessToken:  token,
		RefreshToken: refresh,
	}, nil, nil
}

func (s *service) RefreshToken(refreshToken string) (RefreshTokenResponse, map[string]string, error) {
	// 1. Validate refresh token
	claims, err := s.authMiddleware.ParseRefreshToken(refreshToken)
	if err != nil {
		return RefreshTokenResponse{}, map[string]string{"refresh_token": "Invalid or expired refresh token"}, nil
	}

	// 2. Get user
	var user Profile
	err = s.repo.FindProfileByEmail(&user, claims.Email)
	if err != nil {
		return RefreshTokenResponse{}, nil, fmt.Errorf("user not found: %w", err)
	}

	// 3. Get roles for the user (optional, for access token payload)
	roles, err := s.repo.FindRolesByProfileID(user.ID)
	if err != nil {
		return RefreshTokenResponse{}, nil, fmt.Errorf("failed to load roles: %w", err)
	}

	var tokenRoles []authmiddleware.TokenServiceRole
	for _, r := range roles {
		tokenRoles = append(tokenRoles, authmiddleware.TokenServiceRole{
			ServiceName: r.ServiceName,
			RoleName:    r.RoleName,
		})
	}

	// 4. Generate new tokens
	accessToken, err := s.authMiddleware.GenerateAccessToken(user.Email, tokenRoles)
	if err != nil {
		return RefreshTokenResponse{}, nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	newRefreshToken, err := s.authMiddleware.GenerateRefreshToken(user.Email)
	if err != nil {
		return RefreshTokenResponse{}, nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// 5. Return both
	return RefreshTokenResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
	}, nil, nil
}

func (s *service) ChangePassword(req ChangePasswordRequest, token string) (map[string]string, error) {
	// ✅ Parse token
	claims, err := s.authMiddleware.ParseAccessToken(token)
	if err != nil {
		return map[string]string{"token": "invalid or expired access token"}, nil
	}

	if claims.Email != req.Email {
		return map[string]string{"email": "email does not match access token"}, nil
	}

	var user Profile
	err = s.repo.FindProfileByEmail(&user, req.Email)
	if err != nil {
		return map[string]string{"email": "user not found"}, nil
	}
	if user.IsDeleted {
		return map[string]string{"email": "user not active"}, nil
	}

	// ✅ Check old password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		return map[string]string{"password": "incorrect current password"}, nil
	}

	// ✅ Hash and update new password
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("password hash failed: %w", err)
	}

	user.Password = string(newHash)
	user.ModifiedAt = time.Now()
	user.ModifiedBy = "self"

	if err := s.repo.UpdateUserPassword(&user); err != nil {
		return nil, err
	}

	return nil, nil
}

func (s *service) ValidateToken(token string) (ValidateTokenResponse, map[string]string, error) {
	claims, err := s.authMiddleware.ParseAccessToken(token)
	if err != nil {
		return ValidateTokenResponse{}, map[string]string{"token": "invalid or expired"}, nil
	}

	var tokenRoles []ServiceRoleResponse
	for _, r := range claims.Services {
		tokenRoles = append(tokenRoles, ServiceRoleResponse{
			ServiceName: r.ServiceName,
			RoleName:    r.RoleName,
		})
	}

	return ValidateTokenResponse{
		Email:    claims.Email,
		Services: tokenRoles,
	}, nil, nil
}
