package auth

import (
	"github.com/gin-gonic/gin"
	"myiradat-backend-auth/internal/response"
	"myiradat-backend-auth/internal/validation"
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
