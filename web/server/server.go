package server

import (
	"context"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/spf13/viper"

	// Black import (_) is for running a package's init() function without using its other contents.
	"github.com/rs/zerolog/log"
	_ "github.com/yunkon-kim/knock-knock/internal/config"
	_ "github.com/yunkon-kim/knock-knock/internal/logger"

	middlewares "github.com/yunkon-kim/knock-knock/pkg/api/rest/middlewares/custom-middlewares"
	"github.com/yunkon-kim/knock-knock/pkg/iam"
	"github.com/yunkon-kim/knock-knock/web/routes"
)

const (
	infoColor    = "\033[1;34m%s\033[0m"
	noticeColor  = "\033[1;36m%s\033[0m"
	warningColor = "\033[1;33m%s\033[0m"
	errorColor   = "\033[1;31m%s\033[0m"
	debugColor   = "\033[0;36m%s\033[0m"
)

var (
	// Session store의 키 값
	// TODO: randomize it
	key = []byte("super-secret-key")
)

// TemplateRenderer is a custom html/template renderer for Echo framework
type TemplateRenderer struct {
	templates *template.Template
}

// Render renders a template document
func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

func RunFrontendServer(port string) {

	projectRoot := viper.GetString("knockknock.root")

	e := echo.New()

	e.HTTPErrorHandler = func(err error, c echo.Context) {
		// Handle not found error
		if he, ok := err.(*echo.HTTPError); ok && he.Code == http.StatusNotFound {
			// Serve your custom error page
			err = c.File(projectRoot + "/web/templates/pages-misc-error.html")
			if err != nil {
				c.Logger().Error(err)
			}
			return
		}

		// Default error handling
		e.DefaultHTTPErrorHandler(err, c)
	}

	// Middleware for session management
	// Options stores configuration for a session or session store.
	// Fields are a subset of http.Cookie fields.
	// https://pkg.go.dev/github.com/gorilla/sessions@v1.2.1#Options
	store := sessions.NewCookieStore([]byte(key))
	// store.MaxAge(60 * 30)
	e.Use(session.Middleware(store))

	// Custom logger middleware with zerolog
	e.Use(middlewares.Zerologger())

	e.Use(middleware.Recover())
	// limit the application to 20 requests/sec using the default in-memory store
	e.Use(middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(30)))

	// // Path normalization middleware, which handles like main an main.html as the same path
	// e.Pre(func(next echo.HandlerFunc) echo.HandlerFunc {
	// 	return func(c echo.Context) error {
	// 		c.Request().URL.Path = strings.TrimSuffix(c.Request().URL.Path, ".html")
	// 		return next(c)
	// 	}
	// })

	e.HideBanner = true

	// Static files
	// e.Static("/html", "../../web/templates")
	e.Static("/assets", projectRoot+"/web/assets")
	e.Static("/fonts", projectRoot+"/web/fonts")
	e.Static("/img", projectRoot+"/web/assets/img")

	// Templates
	renderer := &TemplateRenderer{
		templates: template.Must(template.ParseGlob(projectRoot + "/web/templates/*.html")),
	}
	e.Renderer = renderer

	// Routes
	routes.Auth(e)

	g := e.Group("/kk")
	g.Use(iam.SessionCheckerMW)
	routes.Main(g)

	svc := g.Group("/svc")
	routes.SecurityGroup(svc)
	routes.LoadBalancer(svc)
	routes.IpACLGroup(svc)

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

		fmt.Println("\n[Stop] Knock-knock frontend server")
		log.Info().Msg("stopping Knock-knock frontend server")
		ctx, cancel := context.WithTimeout(context.TODO(), 3*time.Second)
		defer cancel()

		if err := e.Shutdown(ctx); err != nil {
			e.Logger.Panic(err)
		}
	}(&wg)

	log.Info().Msg("starting Knock-knock frontend server")
	port = fmt.Sprintf(":%s", port)
	if err := e.Start(port); err != nil && err != http.ErrServerClosed {
		log.Error().Err(err).Msg("shuttig down the frontend server")
		e.Logger.Panic("shuttig down the frontend server")
	}

	wg.Wait()
}

func DisplayEndpoints() {
	selfEndpoint := viper.GetString("self.endpoint")

	// Split the selfEndpoint string based on the colon delimiter
	endpointParts := strings.Split(selfEndpoint, ":")

	// Retrieve the IP address from the first element of the resulting slice
	ip := endpointParts[0]

	frontendUrl := " http://" + ip + ":8888/"

	fmt.Println(" Access to Knock-knock website")
	fmt.Printf(noticeColor, frontendUrl)
	fmt.Println("\n ")
}
