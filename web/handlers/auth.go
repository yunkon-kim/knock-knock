package handlers

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo/v4"

	"github.com/labstack/echo-contrib/session"
	"github.com/rs/zerolog/log"
	"github.com/yunkon-kim/knock-knock/internal/config"
	_ "github.com/yunkon-kim/knock-knock/internal/logger"
	"github.com/yunkon-kim/knock-knock/internal/slack"
	"golang.org/x/oauth2"

	"github.com/yunkon-kim/knock-knock/pkg/iam"
)

var (
	once sync.Once

	keycloakOauthConfig *oauth2.Config

	// TODO: randomize it
	oauthStateString = "pseudo-random"

	// Session store의 키 값
	// TODO: randomize it
	key = []byte("super-secret-key")

	maxAge = 60 * 30 // 30 minutes
)

func Index(c echo.Context) error {
	return c.Render(http.StatusOK, "index.html", nil)
}

func LoginKeycloak(c echo.Context) error {

	// Keycloak OAuth2 configuration
	once.Do(func() {
		keycloakOauthConfig = &oauth2.Config{
			ClientID:     config.Keycloak.Frontend.ClientId,
			ClientSecret: config.Keycloak.Frontend.ClientSecret,
			RedirectURL:  config.Keycloak.Frontend.RedirectUrl,
			Endpoint: oauth2.Endpoint{
				AuthURL:  config.Keycloak.AuthUrl,
				TokenURL: config.Keycloak.TokenUrl,
			},
		}
	})
	time.Sleep(5 * time.Millisecond)

	url := keycloakOauthConfig.AuthCodeURL(oauthStateString)
	return c.Redirect(http.StatusMovedPermanently, url)
}

func AuthCallback(c echo.Context) error {

	log.Trace().Msgf("%v", c.Request().Header)
	log.Debug().Msgf("%v", c.Request().FormValue("code"))

	code := c.Request().FormValue("code")

	token, err := keycloakOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		log.Error().Msgf("failed to exchange token: %v", err)
		return c.String(http.StatusBadRequest, err.Error())
	}
	log.Trace().Msgf("token: %v", token)
	log.Trace().Msgf("token.AccessToken: %v", token.AccessToken)

	// Parse JWT token
	claims := jwt.MapClaims{}
	jwtToken, err := jwt.ParseWithClaims(token.AccessToken, claims, iam.GetKey)
	if err != nil {
		return c.String(http.StatusBadRequest, err.Error())
	}

	// Get claims
	claims, ok := jwtToken.Claims.(jwt.MapClaims) // by default claims is of type `jwt.MapClaims`
	if !ok {
		log.Error().Msgf("failed to cast claims as jwt.MapClaims")
		c.String(http.StatusUnauthorized, "failed to cast claims as jwt.MapClaims")
	}

	roles := iam.ParseRealmRoles(claims)

	// Check this user's role
	var role = ""
	if iam.HasRole(roles, "maintainer") {
		role = "Maintainer"
	} else if iam.HasRole(roles, "admin") {
		role = "Admin"
	} else if iam.HasRole(roles, "user") {
		role = "User"
	} else {
		role = "Guest"
	}

	// Get expiry time from claims
	exp, ok := claims["exp"].(float64)
	if !ok {
		// If the exp claim is missing or not of the expected type
		log.Debug().Msgf("Unable to find or parse expiry time from token")
		return c.String(http.StatusNotFound, "Unable to find or parse expiry time from token")
	}
	expiryTime := time.Unix(int64(exp), 0)         // Unix time
	expiredTime := expiryTime.Format(time.RFC3339) // RFC3339 time

	// Set session
	sess, err := session.Get("session", c)
	if err != nil {
		log.Error().Err(err).Msg("")
		return c.String(http.StatusInternalServerError, "/")
	}

	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
	}

	// Set user as authenticated
	sess.Values["authenticated"] = true
	sess.Values["token"] = jwtToken.Raw
	// Set user name
	sess.Values["name"] = claims["name"]
	sess.Values["role"] = role
	sess.Values["expired-time"] = expiredTime
	// Set more values here
	// ...

	// for key, value := range sess.Values {
	// 	log.Debug().Msgf("Key: %s, Value: %v", key, value)
	// }

	err = sess.Save(c.Request(), c.Response())
	if err != nil {
		log.Error().Err(err).Msg("")
		return c.String(http.StatusInternalServerError, err.Error())
	}

	// Set cookie
	// Set cookie for username
	nameCookie := &http.Cookie{
		Name:     "name",
		Value:    claims["name"].(string),
		Path:     "/",
		HttpOnly: false,
	}
	c.SetCookie(nameCookie)

	// Set cookie for role
	roleCookie := &http.Cookie{
		Name:     "role",
		Value:    role,
		Path:     "/",
		HttpOnly: false,
	}
	c.SetCookie(roleCookie)

	// logging
	log.Debug().Msgf("Name cookie: %+v", nameCookie)
	log.Debug().Msgf("Role cookie: %+v", roleCookie)

	slack.PostMessage(fmt.Sprintf("%s logged in", claims["name"]))

	return c.Redirect(http.StatusFound, "/kk/home.html")
}
