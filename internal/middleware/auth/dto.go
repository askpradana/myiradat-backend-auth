package auth

type TokenServiceRole struct {
	ServiceName string
	RoleName    string
}

type RefreshTokenClaims struct {
	Email string
}
