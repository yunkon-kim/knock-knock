package handlers

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/spf13/viper"

	"github.com/labstack/echo-contrib/session"
	"github.com/rs/zerolog/log"
	_ "github.com/yunkon-kim/knock-knock/internal/logger"
	"golang.org/x/oauth2"
)

var (
	keycloakOauthConfig *oauth2.Config

	// TODO: randomize it
	oauthStateString = "pseudo-random"

	// Session store의 키 값
	// TODO: randomize it
	key = []byte("super-secret-key")
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
		c.String(http.StatusUnauthorized, "failed to cast claims as jwt.MapClaims")
	}

	// Set session
	sess, _ := session.Get("session", c)

	// Options stores configuration for a session or session store.
	// Fields are a subset of http.Cookie fields.
	// https://pkg.go.dev/github.com/gorilla/sessions@v1.2.1#Options
	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: true,
	}
	// Set user as authenticated
	sess.Values["authenticated"] = true
	// Set user name
	sess.Values["name"] = claims["name"]
	// Set more values here
	// ...
	sess.Save(c.Request(), c.Response())

	return c.Redirect(http.StatusFound, "http://localhost:8888/main/dashboard.html")
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
