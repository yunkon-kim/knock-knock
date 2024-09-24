package controller

import (
	"context"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
	"github.com/yunkon-kim/knock-knock/internal/config"
	"github.com/yunkon-kim/knock-knock/pkg/iam"
	"golang.org/x/oauth2"
)

var (
	keycloakOauthConfig *oauth2.Config

	// TODO: randomize it
	oauthStateString = "pseudo-random"

	// Session store의 키 값
	// TODO: randomize it
	// key = []byte("super-secret-key")

	// maxAge = 60 * 30 // 30 minutes
)

func init() {
	// Keycloak OAuth2 configuration
	keycloakOauthConfig = &oauth2.Config{
		ClientID:     config.Keycloak.Backend.ClientId,
		ClientSecret: config.Keycloak.Backend.ClientSecret,
		RedirectURL:  config.Keycloak.Backend.RedirectUrl,
		Endpoint: oauth2.Endpoint{
			AuthURL:  config.Keycloak.AuthUrl,
			TokenURL: config.Keycloak.TokenUrl,
		},
	}

}

func LoginKeycloak(c echo.Context) error {

	// Keycloak OAuth2 configuration
	keycloakOauthConfig = &oauth2.Config{
		ClientID:     config.Keycloak.Backend.ClientId,
		ClientSecret: config.Keycloak.Backend.ClientSecret,
		RedirectURL:  config.Keycloak.Backend.RedirectUrl,
		Endpoint: oauth2.Endpoint{
			AuthURL:  config.Keycloak.AuthUrl,
			TokenURL: config.Keycloak.TokenUrl,
		},
	}

	url := keycloakOauthConfig.AuthCodeURL(oauthStateString)
	return c.Redirect(http.StatusMovedPermanently, url)
}

func DisplayToken(c echo.Context) error {

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

	page := fmt.Sprintf(`
<html>
<head>
<script>
function copyToken() {
    var copyText = document.getElementById("tokenArea");
    copyText.select();
    document.execCommand("copy");
}
</script>
</head>
<body>
Copy this token and paste it to the Swagger UI. <br><br>
<button onclick="copyToken()">Click to Copy</button><br>
<textarea id="tokenArea" rows="20" cols="100">Bearer %s</textarea>
</body>
</html>
`, jwtToken.Raw)

	return c.HTML(http.StatusOK, page)
}
