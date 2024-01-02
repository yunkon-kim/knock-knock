package route

import (
	"github.com/labstack/echo/v4"
	"github.com/yunkon-kim/knock-knock/pkg/api/rest/controller"
)

// /knock-knock/nhn/*
func RegisterNHNRoutes(g *echo.Group) {
	g.GET("/token", controller.GetToken)
	g.POST("/tokenId", controller.SetTokenId)
	g.GET("/sg", controller.GetSecurityGroups)
	g.GET("/sg/:id", controller.GetSecurityGroup)
}
