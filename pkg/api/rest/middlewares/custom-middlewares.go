package middlewares

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo-contrib/session"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
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

func SessionChecker(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sess, err := session.Get("session", c)
		if err != nil {
			log.Error().Err(err).Msg("failed to get session")
			return c.Redirect(http.StatusSeeOther, "/")
		}

		expiredTime, ok := sess.Values["expired-time"].(string)
		if !ok {
			log.Error().Msg("failed to cast sess.Values[expired-time] as string")
			// Delete session if it's expired
			sess.Options.MaxAge = -1 //
			sess.Save(c.Request(), c.Response())
			return c.Redirect(http.StatusSeeOther, "/")
		}
		log.Trace().Msgf("sess.Values[expired-time] %v", expiredTime)

		expires, err := time.Parse(time.RFC3339, expiredTime)
		if err != nil {
			log.Error().Err(err).Msg("failed to parse expiredTime")
			// Delete session if it's expired
			sess.Options.MaxAge = -1 //
			sess.Save(c.Request(), c.Response())
			return c.Redirect(http.StatusSeeOther, "/")
		}

		if time.Now().After(expires) {
			log.Error().Msg("session expired")
			// Delete session if it's expired
			sess.Options.MaxAge = -1 //
			sess.Save(c.Request(), c.Response())
			return c.Redirect(http.StatusSeeOther, "/")
		}

		log.Trace().Msgf("sess.Values[authenticated]: %v", sess.Values["authenticated"])
		log.Trace().Msgf("sess.Values[token]: %v", sess.Values["token"])
		log.Trace().Msgf("sess.Values[name]: %v", sess.Values["name"])
		log.Trace().Msgf("sess.Values[role]: %v", sess.Values["role"])

		return next(c)
	}
}

// JWTAuth initializes and returns the JWT middleware.
func JWTAuth() echo.MiddlewareFunc {
	config := echojwt.Config{
		KeyFunc:        getKey,
		SuccessHandler: retrospectToken,
	}

	return echojwt.WithConfig(config)
}

// parseKeycloakRSAPublicKey parses a base64 encoded public key into an rsa.PublicKey.
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

// getKey is the KeyFunc for the JWT middleware to supply the key for verification.
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

// retrospectToken is the SuccessHandler for the JWT middleware.
// It will be called if jwt.Parse succeeds and set the claims in the context.
// (Briefly, it is the process of checking whether a (previously) issued token is still valid or not.)
func retrospectToken(c echo.Context) {
	log.Debug().Msg("Start - retrospectToken, which is the SuccessHandler")

	var baseUrl = viper.GetString("keycloak.serverUrl")
	var clientID = viper.GetString("keycloak.clientId")
	var clientSecret = viper.GetString("keycloak.clientSecret")
	var realm = viper.GetString("keycloak.realm")

	token, ok := c.Get("user").(*jwt.Token) // by default token is stored under `user` key
	if !ok {
		c.String(http.StatusUnauthorized, "JWT token missing or invalid")
	}
	claims, ok := token.Claims.(jwt.MapClaims) // by default claims is of type `jwt.MapClaims`
	if !ok {
		c.String(http.StatusUnauthorized, "failed to cast claims as jwt.MapClaims")
	}

	// log.Trace().Msgf("token: %+v", token)
	log.Trace().Msgf("token.Raw: %+v", token.Raw)
	log.Trace().Msgf("claims: %+v", claims)

	var ctx = c.Request().Context()
	// c.Set(fmt.Sprint(enums.ContextKeyClaims), claims)

	client := gocloak.NewClient(baseUrl)

	rptResult, err := client.RetrospectToken(ctx, token.Raw, clientID, clientSecret, realm)
	if err != nil {
		c.String(http.StatusUnauthorized, "Inspection failed:"+err.Error())
	}

	log.Trace().Msgf("rptResult: %+v", rptResult)

	if !*rptResult.Active {
		c.String(http.StatusUnauthorized, "Token is not active")
	}

	log.Debug().Msg("End - retrospectToken, which is the SuccessHandler")
}
