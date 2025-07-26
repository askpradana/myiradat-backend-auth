package auth

import (
	"myiradat-backend-auth/internal/configs"
	"myiradat-backend-auth/internal/middleware"
	"myiradat-backend-auth/internal/response"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

type Handler struct {
	service   Service
	validator *validator.Validate
}

func NewHandler(s Service) *Handler {
	return &Handler{
		service:   s,
		validator: validator.New(),
	}
}

func HttpHandler(r *gin.Engine) {
	jwtConfig := configs.InitJWTConfig()
	jwtGenerator := middleware.NewJWTGenerator(jwtConfig)

	authRepo := NewRepository(configs.Database.DbUser())
	authService := NewService(authRepo, jwtGenerator)
	authHandler := NewHandler(authService)

	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Auth Service is running in docker!"})
	})

	authGroup := r.Group("/auth")
	{
		authGroup.POST("/register", authHandler.Register)
		authGroup.POST("/login", authHandler.Login)
		authGroup.POST("/refresh-token", authHandler.RefreshToken)
		authGroup.POST("/change-password", middleware.AuthMiddleware("user"), authHandler.ChangePassword)
		authGroup.POST("/logout", middleware.AuthMiddleware("user"), authHandler.Logout)
		authGroup.GET("/service-roles", authHandler.GetServiceRoles)
		authGroup.GET("/me", middleware.AuthMiddleware("user"), authHandler.GetMe)
	}
}

func (h *Handler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, err.Error())
		return
	}

	if err := h.validator.Struct(req); err != nil {
		response.Error(c, err.Error())
		return
	}

	data, err := h.service.Register(req)
	if err != nil {
		response.ServerError(c, err.Error())
		return
	}

	response.Success(c, data)
}

func (h *Handler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, err.Error())
		return
	}

	if err := h.validator.Struct(req); err != nil {
		response.Error(c, err.Error())
		return
	}

	data, err := h.service.Login(req)
	if err != nil {
		response.ServerError(c, err.Error())
		return
	}

	response.Success(c, data)
}

func (h *Handler) RefreshToken(c *gin.Context) {
	refreshToken := c.Query("refresh_token")
	if refreshToken == "" {
		response.Error(c, "refresh_token is required")
		return
	}

	data, err := h.service.RefreshToken(refreshToken)
	if err != nil {
		response.ServerError(c, err.Error())
		return
	}

	response.Success(c, data)
}

func (h *Handler) ChangePassword(c *gin.Context) {
	email := c.GetString("email")

	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, err.Error())
		return
	}

	if err := h.validator.Struct(req); err != nil {
		response.Error(c, err.Error())
		return
	}

	if err := h.service.ChangePassword(req, email); err != nil {
		response.ServerError(c, err.Error())
		return
	}

	response.Success(c, "password updated successfully")
}

func (h *Handler) Logout(c *gin.Context) {
	email := c.GetString("email")
	if err := h.service.Logout(email); err != nil {
		response.ServerError(c, err.Error())
		return
	}
	response.Success(c, "logout successful")
}

func (h *Handler) ValidateToken(c *gin.Context) {
	token := c.GetHeader("Authorization")
	if token == "" {
		response.Error(c, "Authorization header is required")
		return
	}

	data, err := h.service.ValidateToken(token)
	if err != nil {
		response.ServerError(c, err.Error())
		return
	}

	response.Success(c, data)
}

func (h *Handler) GetServiceRoles(c *gin.Context) {
	data, err := h.service.GetServiceRoles()
	if err != nil {
		response.ServerError(c, err.Error())
		return
	}
	response.Success(c, data)
}

func (h *Handler) GetMe(c *gin.Context) {
	email := c.GetString("email")
	data, err := h.service.GetMe(email)
	if err != nil {
		response.ServerError(c, err.Error())
		return
	}
	response.Success(c, data)
}
