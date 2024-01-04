package routes

import (
	"github.com/yunkon-kim/knock-knock/web/handlers"

	"github.com/labstack/echo/v4"
)

func Init(e *echo.Echo) {
	e.GET("/", handlers.LoginKeycloak)
	e.GET("/auth/callback", handlers.AuthCallback)
}

func Main(g *echo.Group) {
	g.GET("/dashboard.html", handlers.Dashboard)
	g.GET("/tables-basic.html", handlers.TablesBasic)
	
}
