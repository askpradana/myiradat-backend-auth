package auth

import (
	"github.com/gin-gonic/gin"
	"myiradat-backend-auth/internal/response"
	"myiradat-backend-auth/internal/validation"
	"strings"
)

type Handler struct {
	service Service
}

func NewHandler(s Service) *Handler {
	return &Handler{s}
}

func (h *Handler) Register(c *gin.Context) {
	var req RegisterRequest

	// Step 1: Bind JSON
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, gin.H{"request": "invalid json format"})
		return
	}

	// Step 2: Validate input using validator/v10
	if err := validation.Validate.Struct(req); err != nil {
		errs := validation.ParseValidationErrors(err, req)
		response.Error(c, errs)
		return
	}

	// Step 3: Call service layer
	resp, errs, err := h.service.Register(req)

	// Step 4: Handle business logic-level validation errors
	if len(errs) > 0 {
		response.Error(c, errs)
		return
	}

	// Step 5: Handle internal error
	if err != nil {
		response.ServerError(c, "internal server error")
		return
	}

	// Step 6: Success
	response.Success(c, resp)
}

func (h *Handler) Login(c *gin.Context) {
	var req LoginRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, gin.H{"request": "invalid json format"})
		return
	}

	if err := validation.Validate.Struct(req); err != nil {
		errs := validation.ParseValidationErrors(err, req)
		response.Error(c, errs)
		return
	}

	resp, errs, err := h.service.Login(req)

	if len(errs) > 0 {
		response.Error(c, errs)
		return
	}

	if err != nil {
		response.ServerError(c, "internal server error")
		return
	}

	response.Success(c, resp)
}

func (h *Handler) RefreshToken(c *gin.Context) {
	var req RefreshTokenRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, gin.H{"refresh_token": "Invalid JSON body"})
		return
	}

	if err := validation.Validate.Struct(req); err != nil {
		errors := validation.ParseValidationErrors(err, req)
		response.Error(c, errors)
		return
	}

	resp, fieldErrs, err := h.service.RefreshToken(req.RefreshToken)
	if len(fieldErrs) > 0 {
		response.Error(c, fieldErrs)
		return
	}
	if err != nil {
		response.ServerError(c, "Internal server error")
		return
	}

	response.Success(c, resp)
}

func (h *Handler) ValidateToken(c *gin.Context) {
	var req ValidateTokenRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, gin.H{"token": "Invalid JSON body"})
		return
	}

	if err := validation.Validate.Struct(req); err != nil {
		errors := validation.ParseValidationErrors(err, req)
		response.Error(c, errors)
		return
	}

	data, fieldErrs, err := h.service.ValidateToken(req.Token)
	if len(fieldErrs) > 0 {
		response.Error(c, fieldErrs)
		return
	}
	if err != nil {
		response.ServerError(c, "Internal server error")
		return
	}

	response.Success(c, data)
}

func (h *Handler) ChangePassword(c *gin.Context) {
	var req ChangePasswordRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, gin.H{"request": "invalid json format"})
		return
	}

	if err := validation.Validate.Struct(req); err != nil {
		response.Error(c, validation.ParseValidationErrors(err, req))
		return
	}

	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		response.Error(c, gin.H{"token": "missing or invalid authorization header"})
		return
	}
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	// pass to service
	errs, err := h.service.ChangePassword(req, tokenStr)
	if len(errs) > 0 {
		response.Error(c, errs)
		return
	}
	if err != nil {
		response.ServerError(c, "internal server error")
		return
	}

	response.Success(c, gin.H{"message": "password changed successfully"})
}
