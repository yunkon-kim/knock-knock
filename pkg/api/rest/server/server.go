// Package server is to handle REST API
package server

import (
	"context"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/viper"
	"github.com/yunkon-kim/knock-knock/pkg/api/rest/controller"
	"github.com/yunkon-kim/knock-knock/pkg/api/rest/middlewares"
	"github.com/yunkon-kim/knock-knock/pkg/api/rest/route"

	"fmt"
	"os"

	"net/http"

	// REST API (echo)
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	// echo-swagger middleware
	echoSwagger "github.com/swaggo/echo-swagger"
	_ "github.com/yunkon-kim/knock-knock/pkg/api/rest/docs"

	// Black import (_) is for running a package's init() function without using its other contents.
	"github.com/rs/zerolog/log"
	_ "github.com/yunkon-kim/knock-knock/internal/config"
	_ "github.com/yunkon-kim/knock-knock/internal/logger"
)

//var masterConfigInfos confighandler.MASTERCONFIGTYPE

const (
	infoColor    = "\033[1;34m%s\033[0m"
	noticeColor  = "\033[1;36m%s\033[0m"
	warningColor = "\033[1;33m%s\033[0m"
	errorColor   = "\033[1;31m%s\033[0m"
	debugColor   = "\033[0;36m%s\033[0m"
)

const (
	website = " https://github.com/yunkon-kim/knock-knock"
	banner  = `    
                                         
 ██████╗ ███████╗ █████╗ ██████╗ ██╗   ██╗
 ██╔══██╗██╔════╝██╔══██╗██╔══██╗╚██╗ ██╔╝
 ██████╔╝█████╗  ███████║██║  ██║ ╚████╔╝ 
 ██╔══██╗██╔══╝  ██╔══██║██║  ██║  ╚██╔╝  
 ██║  ██║███████╗██║  ██║██████╔╝   ██║   
 ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝    ╚═╝   

 Knock-knock
 ________________________________________________`
)

// RunServer func start Rest API server

// @title Knock-knock REST API
// @version latest
// @description Knock-knock REST API

// @contact.name API Support
// @contact.url http://AN_ORG.github.io
// @contact.email AN_EMAIL

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @BasePath /knock-knock

// @securityDefinitions.apikey Bearer
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token (get token in http://localhost:8056/auth)
func RunServer(port string) {

	log.Info().Msg("Setting Knock-knock REST API server")

	e := echo.New()

	// Middleware
	// e.Use(middleware.Logger()) // default logger middleware in echo

	// Custom logger middleware with zerolog
	e.Use(middlewares.Zerologger())

	e.Use(middleware.Recover())
	// limit the application to 20 requests/sec using the default in-memory store
	e.Use(middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(20)))

	e.HideBanner = true
	//e.colorer.Printf(banner, e.colorer.Red("v"+Version), e.colorer.Blue(website))

	allowedOrigins := viper.GetString("api.allow.origins")
	if allowedOrigins == "" {
		log.Fatal().Msg("allow_ORIGINS env variable for CORS is " + allowedOrigins +
			". Please provide a proper value and source setup.env again. EXITING...")
	}

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{allowedOrigins},
		AllowMethods: []string{http.MethodGet, http.MethodPut, http.MethodPost, http.MethodDelete},
	}))

	// // identity and access management by keycloak
	// baseUrl := viper.GetString("keycloak.baseUrl")
	// realm := viper.GetString("keycloak.realm")
	// clientId := viper.GetString("keycloak.clientId")
	// clientSecret := viper.GetString("keycloak.clientSecret")

	// iam := iam.NewIdentityAccessManager(baseUrl, realm, clientId, clientSecret)

	// Conditions to prevent abnormal operation due to typos (e.g., ture, falss, etc.)
	enableAuth := viper.GetString("api.auth.enabled") == "true"

	apiUser := viper.GetString("api.username")
	apiPass := viper.GetString("api.password")

	if enableAuth {
		// e.Use(middleware.BasicAuthWithConfig(middleware.BasicAuthConfig{
		// 	// Skip authentication for some routes that do not require authentication
		// 	Skipper: func(c echo.Context) bool {
		// 		if c.Path() == "/knock-knock/health" ||
		// 			c.Path() == "/knock-knock/httpVersion" {
		// 			return true
		// 		}
		// 		return false
		// 	},
		// 	Validator: func(username, password string, c echo.Context) (bool, error) {
		// 		// Be careful to use constant time comparison to prevent timing attacks
		// 		if subtle.ConstantTimeCompare([]byte(username), []byte(apiUser)) == 1 &&
		// 			subtle.ConstantTimeCompare([]byte(password), []byte(apiPass)) == 1 {
		// 			return true, nil
		// 		}
		// 		return false, nil
		// 	},
		// }))
	}

	fmt.Println("\n \n ")
	fmt.Print(banner)
	fmt.Println("\n ")
	fmt.Println("\n ")
	fmt.Printf(infoColor, website)
	fmt.Println("\n \n ")

	// Route for system management
	e.GET("/knock-knock/swagger/*", echoSwagger.WrapHandler)
	e.GET("/auth", controller.LoginKeycloak)
	e.GET("/auth/callback", controller.DisplayToken)

	// Knock API group which has /knock-knock as prefix
	groupBase := e.Group("/knock-knock")
	groupBase.GET("/health", controller.RestGetHealth)

	// NHN Cloud API group
	groupNHN := groupBase.Group("/nhn")
	groupNHN.Use(middlewares.JWTAuth())
	route.RegisterNHNRoutes(groupNHN)

	// Sample API group (for developers to add new API)
	groupSample := groupBase.Group("/sample")
	route.RegisterSampleRoutes(groupSample)

	selfEndpoint := viper.GetString("self.endpoint")
	apidashboard := " http://" + selfEndpoint + "/knock-knock/swagger/index.html"

	if enableAuth {
		fmt.Println(" Access to API dashboard" + " (username: " + apiUser + " / password: " + apiPass + ")")
	}
	fmt.Printf(noticeColor, apidashboard)
	fmt.Println("\n ")

	// A context for graceful shutdown (It is based on the signal package)selfEndpoint := os.Getenv("SELF_ENDPOINT")
	// NOTE -
	// Use os.Interrupt Ctrl+C or Ctrl+Break on Windows
	// Use syscall.KILL for Kill(can't be caught or ignored) (POSIX)
	// Use syscall.SIGTERM for Termination (ANSI)
	// Use syscall.SIGINT for Terminal interrupt (ANSI)
	// Use syscall.SIGQUIT for Terminal quit (POSIX)
	gracefulShutdownContext, stop := signal.NotifyContext(context.TODO(),
		os.Interrupt, syscall.SIGKILL, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	defer stop()

	// Wait graceful shutdown (and then main thread will be finished)
	var wg sync.WaitGroup

	wg.Add(1)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()

		// Block until a signal is triggered
		<-gracefulShutdownContext.Done()

		fmt.Println("\n[Stop] Knock-knock REST API server")
		log.Info().Msg("stopping Knock-knock REST API server")
		ctx, cancel := context.WithTimeout(context.TODO(), 3*time.Second)
		defer cancel()

		if err := e.Shutdown(ctx); err != nil {
			e.Logger.Panic(err)
		}
	}(&wg)

	log.Info().Msg("starting Knock-knock REST API server")
	port = fmt.Sprintf(":%s", port)
	if err := e.Start(port); err != nil && err != http.ErrServerClosed {
		e.Logger.Panic("shuttig down the server")
	}

	wg.Wait()
}
