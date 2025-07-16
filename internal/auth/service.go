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
	Logout(email string) (map[string]string, error)
	RefreshToken(refreshToken string) (RefreshTokenResponse, map[string]string, error)
	ChangePassword(req ChangePasswordRequest, email string) (map[string]string, error)
	ValidateToken(token string) (ValidateTokenResponse, map[string]string, error)
	GetServiceRoles() ([]ServiceRoleDTO, error)
	GetMe(email string) (MeResponse, error)
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
			ServiceCode: r.ServiceCode,
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

	// Save refresh token
	if err := s.repo.UpdateRefreshToken(user.ID, refresh); err != nil {
		return LoginResponse{}, nil, err
	}

	return LoginResponse{
		AccessToken:  token,
		RefreshToken: refresh,
	}, nil, nil
}

func (s *service) Logout(email string) (map[string]string, error) {
	// Find user to ensure they exist and are not deleted
	var user Profile
	if err := s.repo.FindProfileByEmail(&user, email); err != nil {
		return map[string]string{"user": "user not found"}, nil
	}
	if user.IsDeleted {
		return map[string]string{"user": "account is inactive"}, nil
	}

	// Clear refresh token in DB
	if err := s.repo.ClearRefreshTokenByEmail(email); err != nil {
		return nil, err
	}

	return nil, nil
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

	if user.RefreshToken != refreshToken {
		return RefreshTokenResponse{}, map[string]string{"token": "refresh token does not match"}, nil
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

	// Generate new access & refresh tokens
	newAccessToken, err := s.authMiddleware.GenerateAccessToken(user.Email, tokenRoles)
	if err != nil {
		return RefreshTokenResponse{}, nil, err
	}

	newRefreshToken, err := s.authMiddleware.GenerateRefreshToken(user.Email)
	if err != nil {
		return RefreshTokenResponse{}, nil, err
	}

	if err := s.repo.UpdateRefreshToken(user.ID, newRefreshToken); err != nil {
		return RefreshTokenResponse{}, nil, err
	}

	return RefreshTokenResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
	}, nil, nil
}

func (s *service) ChangePassword(req ChangePasswordRequest, email string) (map[string]string, error) {
	if req.Email != email {
		return map[string]string{"email": "email does not match access token"}, nil
	}

	var user Profile
	if err := s.repo.FindProfileByEmail(&user, email); err != nil {
		return map[string]string{"email": "user not found"}, nil
	}
	if user.IsDeleted {
		return map[string]string{"email": "account is inactive"}, nil
	}

	// Verify old password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		return map[string]string{"password": "incorrect current password"}, nil
	}

	// Hash new password
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash new password: %w", err)
	}

	// Update
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

	var tokenRoles []ServiceRoleForToken
	for _, r := range claims.Services {
		tokenRoles = append(tokenRoles, ServiceRoleForToken{
			ServiceName: r.ServiceName,
			RoleName:    r.RoleName,
		})
	}

	return ValidateTokenResponse{
		Email:    claims.Email,
		Services: tokenRoles,
	}, nil, nil
}

func (s *service) GetServiceRoles() ([]ServiceRoleDTO, error) {
	services, err := s.repo.FindActiveServiceRoles()
	if err != nil {
		return nil, err
	}

	var result []ServiceRoleDTO
	for _, svc := range services {
		roles, err := s.repo.FindRolesByServiceID(svc.ID)
		if err != nil {
			return nil, err
		}

		var roleDTOs []RoleDTO
		for _, r := range roles {
			roleDTOs = append(roleDTOs, RoleDTO{
				RoleID:      r.ID,
				RoleName:    r.RoleName,
				Description: r.Description,
			})
		}

		result = append(result, ServiceRoleDTO{
			ServiceID:   svc.ID,
			ServiceName: svc.ServiceName,
			RedirectURI: svc.RedirectURI,
			Roles:       roleDTOs,
		})
	}
	return result, nil
}

func (s *service) GetMe(email string) (MeResponse, error) {
	var user Profile
	if err := s.repo.FindProfileByEmail(&user, email); err != nil {
		return MeResponse{}, fmt.Errorf("user not found")
	}

	roles, err := s.repo.FindRolesByProfileID(user.ID)
	if err != nil {
		return MeResponse{}, fmt.Errorf("failed to load roles: %w", err)
	}

	return MeResponse{
		Name:     user.Name,
		Email:    user.Email,
		NoHP:     user.NoHP,
		Services: roles,
	}, nil
}
