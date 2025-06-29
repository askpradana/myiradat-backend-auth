package auth

import (
	"github.com/gin-gonic/gin"
	"myiradat-backend-auth/internal/response"
)

type Handler struct {
	service Service
}

func NewHandler(s Service) *Handler {
	return &Handler{s}
}

func (h *Handler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, gin.H{"request": "invalid json format"})
		return
	}

	resp, errs, err := h.service.Register(req)
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
