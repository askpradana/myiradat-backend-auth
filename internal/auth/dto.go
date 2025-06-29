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
