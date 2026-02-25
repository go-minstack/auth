package main

import (
	"net/http"
	"time"

	"example/auth-hello/dto"

	"github.com/gin-gonic/gin"
	"github.com/go-minstack/auth"
	"github.com/go-minstack/core"
	mgin "github.com/go-minstack/gin"
)

const tokenExpiry = time.Hour

type UserController struct {
	svc *auth.JwtService
}

func NewUserController(svc *auth.JwtService) *UserController {
	return &UserController{svc: svc}
}

func (c *UserController) login(ctx *gin.Context) {
	var input dto.LoginRequestDto
	if err := ctx.ShouldBindJSON(&input); err != nil {
		ctx.JSON(http.StatusBadRequest, dto.NewErrorDto(err))
		return
	}

	// In a real app: look up the user and verify the password.
	// Here we issue a token for any well-formed request.
	token, err := c.svc.Sign(auth.Claims{
		Subject: "user-123",
		Name:    "Alice",
		Roles:   []string{"user"},
	}, tokenExpiry)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, dto.NewErrorDto(err))
		return
	}

	ctx.JSON(http.StatusOK, dto.NewLoginResponseDto(token, int64(tokenExpiry.Seconds())))
}

func (c *UserController) profile(ctx *gin.Context) {
	claims, _ := auth.ClaimsFromContext(ctx)
	ctx.JSON(http.StatusOK, dto.NewProfileDto(claims))
}

func (c *UserController) adminOnly(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, dto.NewMessageDto("welcome, admin"))
}

func registerRoutes(r *gin.Engine, c *UserController, svc *auth.JwtService) {
	r.POST("/api/users/login", c.login)

	protected := r.Group("/api/users", auth.Authenticate(svc))
	protected.GET("/profile", c.profile)
	protected.GET("/admin", auth.RequireRole("admin"), c.adminOnly)
}

func main() {
	app := core.New(mgin.Module(), auth.Module())
	app.Provide(NewUserController)
	app.Invoke(registerRoutes)
	app.Run()
}
