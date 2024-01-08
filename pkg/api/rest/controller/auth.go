package controller

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
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
		RedirectURL:  "http://localhost:8056/auth/callback",
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
	jwtToken, err := jwt.ParseWithClaims(token.AccessToken, claims, getKey)
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
