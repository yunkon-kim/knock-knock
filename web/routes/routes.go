package routes

import (
	"github.com/yunkon-kim/knock-knock/web/handlers"

	"github.com/labstack/echo/v4"
)

func Auth(e *echo.Echo) {
	e.GET("/", handlers.LoginKeycloak)
	e.GET("/auth/callback", handlers.AuthCallback)
}

func Main(g *echo.Group) {
	g.GET("/home.html", handlers.Dashboard)
	g.GET("/security-group.html", handlers.SecurityGroup)
}
