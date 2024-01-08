package handlers

import (
	"net/http"

	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"

	_ "github.com/yunkon-kim/knock-knock/internal/logger"
)

func getTokenFromSession(c echo.Context) (string, error) {

	// get session
	sess, err := session.Get("session", c)
	if err != nil {
		return "", echo.NewHTTPError(http.StatusInternalServerError, "session retrieval failed")
	}
	log.Trace().Msgf("sess: %+v", sess)

	// check type assertion
	token, ok := sess.Values["token"].(string)
	if !ok {
		if sess.Values["token"] == nil {
			return "", echo.NewHTTPError(http.StatusUnauthorized, "token is missing")
		} else {
			return "", echo.NewHTTPError(http.StatusUnauthorized, "invalid token format")
		}
	}

	return token, nil
}
