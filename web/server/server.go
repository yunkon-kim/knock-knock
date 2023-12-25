package server

import (
	"context"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/rs/zerolog/log"

	"github.com/yunkon-kim/knock-knock/web/routes"
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

	e := echo.New()
	// Custom logger middleware with zerolog
	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogError:         true,
		LogRequestID:     true,
		LogRemoteIP:      true,
		LogHost:          true,
		LogMethod:        true,
		LogURI:           true,
		LogUserAgent:     true,
		LogStatus:        true,
		LogLatency:       true,
		LogContentLength: true,
		LogResponseSize:  true,
		// HandleError:      true, // forwards error to the global error handler, so it can decide appropriate status code
		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
			if v.Error == nil {
				log.Info().
					Str("id", v.RequestID).
					Str("remote_ip", v.RemoteIP).
					Str("host", v.Host).
					Str("method", v.Method).
					Str("URI", v.URI).
					Str("user_agent", v.UserAgent).
					Int("status", v.Status).
					Int64("latency", v.Latency.Nanoseconds()).
					Str("latency_human", v.Latency.String()).
					Str("bytes_in", v.ContentLength).
					Int64("bytes_out", v.ResponseSize).
					Msg("request")
			} else {
				log.Error().
					Err(v.Error).
					Str("id", v.RequestID).
					Str("remote_ip", v.RemoteIP).
					Str("host", v.Host).
					Str("method", v.Method).
					Str("URI", v.URI).
					Str("user_agent", v.UserAgent).
					Int("status", v.Status).
					Int64("latency", v.Latency.Nanoseconds()).
					Str("latency_human", v.Latency.String()).
					Str("bytes_in", v.ContentLength).
					Int64("bytes_out", v.ResponseSize).
					Msg("request error")
			}
			return nil
		},
	}))

	e.Use(middleware.Recover())
	// limit the application to 20 requests/sec using the default in-memory store
	e.Use(middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(20)))

	// Static files
	e.Static("../../web/assets", "assets")

	// Templates
	renderer := &TemplateRenderer{
		templates: template.Must(template.ParseGlob("../../web/templates/*.html")),
	}
	e.Renderer = renderer

	// Routes
	routes.Init(e)

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
