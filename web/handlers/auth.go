package handlers

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/spf13/viper"

	"github.com/labstack/echo-contrib/session"
	"github.com/rs/zerolog/log"
	_ "github.com/yunkon-kim/knock-knock/internal/logger"
	"github.com/yunkon-kim/knock-knock/internal/slack"
	"golang.org/x/oauth2"

	"github.com/gookit/goutil"
)

var (
	keycloakOauthConfig *oauth2.Config

	// TODO: randomize it
	oauthStateString = "pseudo-random"

	// Session store의 키 값
	// TODO: randomize it
	key = []byte("super-secret-key")

	maxAge = 60 * 30 // 30 minutes
)

func init() {
	// Keycloak OAuth2 configuration
	keycloakOauthConfig = &oauth2.Config{
		ClientID:     viper.GetString("keycloak.clientId"),
		ClientSecret: viper.GetString("keycloak.clientSecret"),
		RedirectURL:  viper.GetString("keycloak.redirectURL"),
		Endpoint: oauth2.Endpoint{
			AuthURL:  viper.GetString("keycloak.authURL"),
			TokenURL: viper.GetString("keycloak.tokenURL"),
		},
	}

}

func Index(c echo.Context) error {
	return c.Render(http.StatusOK, "index.html", nil)
}

func LoginKeycloak(c echo.Context) error {

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
	jwtToken, err := jwt.ParseWithClaims(token.AccessToken, claims, getKey)
	if err != nil {
		return c.String(http.StatusBadRequest, err.Error())
	}

	// Get claims
	claims, ok := jwtToken.Claims.(jwt.MapClaims) // by default claims is of type `jwt.MapClaims`
	if !ok {
		log.Error().Msgf("failed to cast claims as jwt.MapClaims")
		c.String(http.StatusUnauthorized, "failed to cast claims as jwt.MapClaims")
	}

	roles := parseRealmRoles(claims)

	// Check this user's role
	var role = ""
	if goutil.Contains(roles, "maintainer") {
		role = "Maintainer"
	} else if goutil.Contains(roles, "admin") {
		role = "Admin"
	} else if goutil.Contains(roles, "user") {
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

// parseKeycloakRSAPublicKey parses the RSA public key from the base64 string.
func parseKeycloakRSAPublicKey(base64Str string) (*rsa.PublicKey, error) {
	buf, err := base64.StdEncoding.DecodeString(base64Str)
	if err != nil {
		return nil, err
	}
	parsedKey, err := x509.ParsePKIXPublicKey(buf)
	if err != nil {
		return nil, err
	}
	publicKey, ok := parsedKey.(*rsa.PublicKey)
	if ok {
		return publicKey, nil
	}
	return nil, fmt.Errorf("unexpected key type %T", publicKey)
}

// getKey returns the public key for verifying the JWT token.
func getKey(token *jwt.Token) (interface{}, error) {

	base64Str := viper.GetString("keycloak.realmRS256PublicKey")
	publicKey, _ := parseKeycloakRSAPublicKey(base64Str)

	key, _ := jwk.New(publicKey)

	var pubkey interface{}
	if err := key.Raw(&pubkey); err != nil {
		return nil, fmt.Errorf("unable to get the public key. error: %s", err.Error())
	}

	return pubkey, nil
}

func parseRealmRoles(claims jwt.MapClaims) []string {
	var realmRoles []string = make([]string, 0)

	if claim, ok := claims["realm_access"]; ok {
		if roles, ok := claim.(map[string]interface{})["roles"]; ok {
			for _, role := range roles.([]interface{}) {
				realmRoles = append(realmRoles, role.(string))
			}
		}
	}
	return realmRoles
}
