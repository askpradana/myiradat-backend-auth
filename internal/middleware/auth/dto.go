package auth

type RefreshTokenClaims struct {
	Email string `json:"email"`
}

type TokenServiceRole struct {
	ServiceName string `json:"serviceName"`
	RoleName    string `json:"roleName"`
}

type AccessTokenClaims struct {
	Email    string             `json:"email"`
	Services []TokenServiceRole `json:"services"`
}
