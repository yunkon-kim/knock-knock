package routes

import (
	"github.com/yunkon-kim/knock-knock/web/handlers"

	"github.com/labstack/echo/v4"
)

func Auth(e *echo.Echo) {
	e.GET("/", handlers.Index)
	e.GET("/index.html", handlers.Index)
	e.GET("/index", handlers.Index)
	e.GET("/login", handlers.LoginKeycloak)
	e.GET("/auth/callback", handlers.AuthCallback)
}

func Main(g *echo.Group) {
	g.GET("/home.html", handlers.Dashboard)
	g.GET("/security-group.html", handlers.SecurityGroup)
	g.GET("/load-balancer.html", handlers.LoadBalancer)
	g.GET("/ip-acl-group.html", handlers.IpACLGroup)
	g.GET("/tb-auth-test.html", handlers.TbAuthTest)
}

func SecurityGroup(g *echo.Group) {
	g.POST("/rule", handlers.CreateRule)
	g.DELETE("/rule/:id", handlers.DeleteRule)
}

func LoadBalancer(g *echo.Group) {
	g.PUT("/lb/:lb-id/bind_ipacl_groups", handlers.BindIpACLGroupToLoadBalancer)
}

func IpACLGroup(g *echo.Group) {
	// IP access control list group
	g.POST("/ipacl-groups", handlers.CreateIpACLGroup)
	g.DELETE("/ipacl-groups/:ipacl-group-id", handlers.DeleteIpACLGroup)

	// IP access control list target
	g.GET("/ipacl-targets/:ipacl-group-id", handlers.GetIpACLTarget)
	g.POST("/ipacl-targets", handlers.CreateIpACLTarget)
	g.DELETE("/ipacl-targets/:ipacl-target-id", handlers.DeleteIpACLTarget)

}
