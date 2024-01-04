package middlewares

import (
	"net/http"

	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/rs/zerolog/log"
)

func Zerologger() echo.MiddlewareFunc {
	return middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
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
	})
}

func CheckSession(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sess, _ := session.Get("session", c)
		log.Debug().Msgf("sess.Values[authenticated]: %v", sess.Values["authenticated"])
		log.Debug().Msgf("sess.Values[name]: %v", sess.Values["name"])
		if sess.Values["authenticated"] != true {
			return c.Redirect(http.StatusSeeOther, "/")
		}
		return next(c)
	}
}
