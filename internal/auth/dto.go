package auth

type RegisterRequest struct {
	Name            string               `json:"name" validate:"required,name"`
	NoHP            string               `json:"nohp" validate:"required,nohp"`
	Email           string               `json:"email" validate:"required,email"`
	Password        string               `json:"password" validate:"required,min=8"`
	ConfirmPassword string               `json:"confirmPassword" validate:"eqfield=Password"`
	Services        []ServiceRoleRequest `json:"services" validate:"required,dive"`
}

type ServiceRoleRequest struct {
	ServiceID int `json:"serviceId" validate:"required"`
	RoleID    int `json:"roleId" validate:"required"`
}

type RegisterResponse struct {
	ID    int    `json:"id"`
	Email string `json:"email"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type LoginResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type ServiceRoleResponse struct {
	ServiceName string `json:"serviceName"`
	RoleName    string `json:"roleName"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refreshToken" validate:"required"`
}

type RefreshTokenResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type ValidateTokenRequest struct {
	Token string `json:"token" validate:"required"`
}

type ValidateTokenResponse struct {
	Email    string                `json:"email"`
	Services []ServiceRoleResponse `json:"services"`
}
