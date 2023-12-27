package middlewares

import (
	"net/http"

	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"

	"github.com/rs/zerolog/log"
	_ "github.com/yunkon-kim/knock-knock/internal/logger"
)

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
