package middlewares

import (
	"net/http"
	"time"

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

		expiredTime, ok := sess.Values["expired-time"].(string)
		if !ok {
			log.Error().Msg("failed to cast sess.Values[expired-time] as string")
			// Delete session if it's expired
			sess.Options.MaxAge = -1 //
			sess.Save(c.Request(), c.Response())
			return c.Redirect(http.StatusSeeOther, "/")
		}
		log.Debug().Msgf("sess.Values[expired-time] %v", expiredTime)

		expires, err := time.Parse(time.RFC3339, expiredTime)
		if err != nil {
			log.Error().Err(err).Msg("failed to parse expiredTime")
			// Delete session if it's expired
			sess.Options.MaxAge = -1 //
			sess.Save(c.Request(), c.Response())
			return c.Redirect(http.StatusSeeOther, "/")
		}

		if time.Now().After(expires) {
			log.Info().Msg("session expired")
			// Delete session if it's expired
			sess.Options.MaxAge = -1 //
			sess.Save(c.Request(), c.Response())
			return c.Redirect(http.StatusSeeOther, "/")
		}

		log.Debug().Msgf("sess.Values[authenticated]: %v", sess.Values["authenticated"])
		log.Debug().Msgf("sess.Values[name]: %v", sess.Values["name"])

		return next(c)
	}
}
