package routes

import (
	"github.com/yunkon-kim/knock-knock/web/handlers"

	"github.com/labstack/echo/v4"
)

func Init(e *echo.Echo) {
	e.GET("/", handlers.IndexHandler)
	e.GET("/index", handlers.IndexHandler)
	e.GET("/auth", handlers.LoginKeycloak)
	e.GET("/auth/callback", handlers.AuthCallback)
}

func Main(g *echo.Group) {
	g.GET("", handlers.Main)
}
