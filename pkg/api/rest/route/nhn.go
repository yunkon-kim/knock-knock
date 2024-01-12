package route

import (
	"github.com/labstack/echo/v4"
	"github.com/yunkon-kim/knock-knock/pkg/api/rest/controller"
)

// /knock-knock/nhn/*
func RegisterNHNRoutes(g *echo.Group) {
	g.GET("/token", controller.GetToken)
	g.POST("/tokenId", controller.SetTokenId)

	// Security Group
	g.GET("/sg", controller.GetSecurityGroups)
	g.GET("/sg/:id", controller.GetSecurityGroup)
	g.POST("/sgRule", controller.CreateSecurityGroupRule)
	g.DELETE("/sgRule/:id", controller.DeleteSecurityGroupRule)

	// Network ACL
	g.GET("/acls", controller.GetNetworkACLs)

	// load banalcers
	g.GET("/lbs", controller.GetLoadBalancers)

	// g.PUT("/sg/:id", controller.UpdateSecurityGroup)

}
