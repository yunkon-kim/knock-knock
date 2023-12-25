package routes

import (
	"github.com/yunkon-kim/knock-knock/web/handlers"

	"github.com/labstack/echo/v4"
)

func Init(e *echo.Echo) {
	e.GET("/", handlers.IndexHandler)
}
