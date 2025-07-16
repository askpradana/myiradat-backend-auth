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
	ID    uint   `json:"id"`
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
	Services []ServiceRoleForToken `json:"services"`
}

type ChangePasswordRequest struct {
	Email           string `json:"email" validate:"required,email"`
	Password        string `json:"password" validate:"required"`
	NewPassword     string `json:"newPassword" validate:"required,min=8"`
	ConfirmPassword string `json:"confirmPassword" validate:"required,eqfield=NewPassword"`
}

type ServiceRoleDTO struct {
	ServiceID   int       `json:"serviceId"`
	ServiceName string    `json:"serviceName"`
	Description string    `json:"description"`
	RedirectURI string    `json:"redirectURI"`
	Roles       []RoleDTO `json:"roles"`
}

type RoleDTO struct {
	RoleID      int    `json:"roleId"`
	RoleName    string `json:"roleName"`
	Description string `json:"description"`
}

type ServiceRoleForToken struct {
	ServiceName     string `json:"serviceName"`
	RoleName        string `json:"roleName"`
	ServiceRole     string `json:"serviceRole"`
	RoleDescription string `json:"roleDescription"`
}

type ServiceRoleResponse struct {
	ServiceName     string `json:"serviceName"`
	RoleName        string `json:"roleName"`
	RoleDescription string `json:"roleDescription"`
	RedirectUri     string `json:"redirect_uri"`
	ServiceCode     string `json:"serviceCode"`
	ServiceId       int    `json:"service_id"`
	RoleId          int    `json:"role_id"`
}

type MeResponse struct {
	Name     string                `json:"name"`
	Email    string                `json:"email"`
	NoHP     string                `json:"noHP"`
	Services []ServiceRoleResponse `json:"services"`
}
