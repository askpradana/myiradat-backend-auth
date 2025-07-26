package middleware

type RefreshTokenClaims struct {
	Email string `json:"email"`
}

type TokenServiceRole struct {
	ServiceName string `json:"serviceName"`
	ServiceCode string `json:"serviceCode"`
	RoleName    string `json:"roleName"`
}

type AccessTokenClaims struct {
	Email    string             `json:"email"`
	Services []TokenServiceRole `json:"services"`
}
