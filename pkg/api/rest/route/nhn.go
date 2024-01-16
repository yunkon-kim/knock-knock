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
	g.PUT("/lbs/:id/bind_ipacl_groups", controller.BindIpACLGroupToLoadBalancer)

	// IP access control list group
	g.GET("/lbs/ipacl-groups", controller.GetIpACLGroups)
	g.POST("/lbs/ipacl-groups", controller.CreateIpACLGroup)
	g.DELETE("/lbs/ipacl-groups/:id", controller.DeleteIpACLGroup)

	// IP access control list target
	g.GET("/lbs/ipacl-targets", controller.GetIpACLTargets)
	g.POST("/lbs/ipacl-targets", controller.CreateIpACLTarget)
	g.DELETE("/lbs/ipacl-targets/:id", controller.DeleteIpACLTarget)

	// g.PUT("/sg/:id", controller.UpdateSecurityGroup)

}
