package auth

import (
	"fmt"
	"myiradat-backend-auth/internal/middleware"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Service interface {
	Register(input RegisterRequest) (RegisterResponse, error)
	Login(input LoginRequest) (LoginResponse, error)
	Logout(email string) error
	RefreshToken(refreshToken string) (RefreshTokenResponse, error)
	ChangePassword(req ChangePasswordRequest, email string) error
	ValidateToken(token string) (ValidateTokenResponse, error)
	GetServiceRoles() ([]ServiceRoleDTO, error)
	GetMe(email string) (MeResponse, error)
}

type service struct {
	repo           Repository
	authMiddleware middleware.IJwtTokenGenerator
}

func NewService(r Repository, jwt middleware.IJwtTokenGenerator) Service {
	return &service{
		repo:           r,
		authMiddleware: jwt,
	}
}

func (s *service) Register(input RegisterRequest) (RegisterResponse, error) {
	if s.repo.IsEmailExist(input.Email) {
		return RegisterResponse{}, fmt.Errorf("email %s already exists", input.Email)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return RegisterResponse{}, fmt.Errorf("failed to hash password: %w", err)
	}

	profile := Profile{
		Name:       input.Name,
		Email:      input.Email,
		NoHP:       input.NoHP,
		Password:   string(hashedPassword),
		CreatedAt:  time.Now(),
		CreatedBy:  "system",
		ModifiedAt: time.Now(),
		ModifiedBy: "system",
	}

	if err := s.repo.CreateProfileWithRoles(&profile, input.Services); err != nil {
		if err.Error() == "invalid service and roles" {
			return RegisterResponse{}, fmt.Errorf("invalid service and roles")
		}
		return RegisterResponse{}, fmt.Errorf("failed to create profile with roles: %w", err)
	}

	return RegisterResponse{
		ID:    profile.ID,
		Email: profile.Email,
	}, nil
}

func (s *service) Login(input LoginRequest) (LoginResponse, error) {
	var user Profile
	if err := s.repo.FindProfileByEmail(&user, input.Email); err != nil {
		return LoginResponse{}, fmt.Errorf("email not found: %s", input.Email)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
		return LoginResponse{}, fmt.Errorf("incorrect password")
	}

	roles, err := s.repo.FindRolesByProfileID(user.ID)
	if err != nil {
		return LoginResponse{}, fmt.Errorf("failed to retrieve user roles: %w", err)
	}

	tokenRoles := make([]middleware.TokenServiceRole, len(roles))
	for i, r := range roles {
		tokenRoles[i] = middleware.TokenServiceRole{
			ServiceCode: r.ServiceCode,
			RoleName:    r.RoleName,
		}
	}

	accessToken, err := s.authMiddleware.GenerateAccessToken(user.Email, tokenRoles)
	if err != nil {
		return LoginResponse{}, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := s.authMiddleware.GenerateRefreshToken(user.Email)
	if err != nil {
		return LoginResponse{}, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	if err := s.repo.UpdateRefreshToken(user.ID, refreshToken); err != nil {
		return LoginResponse{}, fmt.Errorf("failed to update refresh token: %w", err)
	}

	return LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *service) Logout(email string) error {
	var user Profile
	if err := s.repo.FindProfileByEmail(&user, email); err != nil {
		return fmt.Errorf("user with email %s not found: %w", email, err)
	}
	if user.IsDeleted {
		return fmt.Errorf("user with email %s is deleted", email)
	}

	if err := s.repo.ClearRefreshTokenByEmail(email); err != nil {
		return fmt.Errorf("failed to clear refresh token: %w", err)
	}

	return nil
}

func (s *service) RefreshToken(refreshToken string) (RefreshTokenResponse, error) {
	claims, err := s.authMiddleware.ParseRefreshToken(refreshToken)
	if err != nil {
		return RefreshTokenResponse{}, fmt.Errorf("invalid refresh token: %w", err)
	}

	var user Profile
	if err := s.repo.FindProfileByEmail(&user, claims.Email); err != nil {
		return RefreshTokenResponse{}, fmt.Errorf("user not found: %w", err)
	}

	if user.RefreshToken != refreshToken {
		return RefreshTokenResponse{}, fmt.Errorf("refresh token mismatch")
	}

	roles, err := s.repo.FindRolesByProfileID(user.ID)
	if err != nil {
		return RefreshTokenResponse{}, fmt.Errorf("failed to retrieve roles: %w", err)
	}

	var tokenRoles []middleware.TokenServiceRole
	for _, r := range roles {
		tokenRoles = append(tokenRoles, middleware.TokenServiceRole{
			ServiceName: r.ServiceName,
			RoleName:    r.RoleName,
		})
	}

	newAccessToken, err := s.authMiddleware.GenerateAccessToken(user.Email, tokenRoles)
	if err != nil {
		return RefreshTokenResponse{}, fmt.Errorf("failed to generate new access token: %w", err)
	}

	newRefreshToken, err := s.authMiddleware.GenerateRefreshToken(user.Email)
	if err != nil {
		return RefreshTokenResponse{}, fmt.Errorf("failed to generate new refresh token: %w", err)
	}

	if err := s.repo.UpdateRefreshToken(user.ID, newRefreshToken); err != nil {
		return RefreshTokenResponse{}, fmt.Errorf("failed to update refresh token: %w", err)
	}

	return RefreshTokenResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
	}, nil
}

func (s *service) ChangePassword(req ChangePasswordRequest, email string) error {
	if req.Email != email {
		return fmt.Errorf("email mismatch: %s != %s", req.Email, email)
	}

	var user Profile
	if err := s.repo.FindProfileByEmail(&user, email); err != nil {
		return fmt.Errorf("user not found: %w", err)
	}
	if user.IsDeleted {
		return fmt.Errorf("cannot change password: user is deleted")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		return fmt.Errorf("old password is incorrect")
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash new password: %w", err)
	}

	user.Password = string(newHash)
	user.ModifiedAt = time.Now()
	user.ModifiedBy = "self"

	if err := s.repo.UpdateUserPassword(&user); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}

func (s *service) ValidateToken(token string) (ValidateTokenResponse, error) {
	claims, err := s.authMiddleware.ParseAccessToken(token)
	if err != nil {
		return ValidateTokenResponse{}, fmt.Errorf("invalid access token: %w", err)
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
	}, nil
}

func (s *service) GetServiceRoles() ([]ServiceRoleDTO, error) {
	services, err := s.repo.FindActiveServiceRoles()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch service roles: %w", err)
	}

	var result []ServiceRoleDTO
	for _, svc := range services {
		roles, err := s.repo.FindRolesByServiceID(svc.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch roles for service ID %d: %w", svc.ID, err)
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
		return MeResponse{}, fmt.Errorf("user not found: %w", err)
	}

	roles, err := s.repo.FindRolesByProfileID(user.ID)
	if err != nil {
		return MeResponse{}, fmt.Errorf("failed to retrieve roles: %w", err)
	}

	return MeResponse{
		Name:     user.Name,
		Email:    user.Email,
		NoHP:     user.NoHP,
		Services: roles,
	}, nil
}
