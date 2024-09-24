package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-resty/resty/v2"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
	"github.com/yunkon-kim/knock-knock/internal/config"
	"github.com/yunkon-kim/knock-knock/pkg/api/rest/model"
)

type AuthsInfo struct {
	Authenticated bool   `json:"authenticated"`
	Role          string `json:"role"`
	Name          string `json:"name"`
	ExpiredTime   string `json:"expired-time"`
	Token         string `json:"token"`
}

///////////////////////////////////////////////////////////////////////////////////////////////////////

func TbAuthTest(c echo.Context) error {

	token, err := getTokenFromSession(c)
	if err != nil {
		log.Error().Err(err).Msg("")
		return c.JSON(http.StatusInternalServerError, err)
	}

	log.Debug().Msgf("token: %v", token)

	client := resty.New()

	tbRestEndpoint := config.Tumblebug.RestUrl
	// Set API URL
	urlTbAuthTest := fmt.Sprintf("%s/auth/test", tbRestEndpoint)

	// Set Resty
	resp, err := client.R().
		SetAuthToken(token).
		SetHeader("Content-Type", "application/json").
		Get(urlTbAuthTest)

	if err != nil {
		return err
	}

	// Check response status code
	if resp.StatusCode() != http.StatusOK {
		log.Error().Msgf("failed tb auth test(status code: %d)", resp.StatusCode())
		res := model.BasicResponse{
			Result: "failed tb auth test",
			Error:  nil,
		}
		return c.JSON(http.StatusInternalServerError, res)
	}

	// Print result
	log.Debug().Msgf("Response Status Code: %d", resp.StatusCode())
	log.Trace().Msgf("Response Body: %s", resp.String())

	// Parse response
	authInfo := new(AuthsInfo)

	err = json.Unmarshal(resp.Body(), authInfo)
	if err != nil {
		log.Error().Err(err).Msg("failed to unmarshal response")
		res := model.BasicResponse{
			Result: "failed to unmarshal response",
			Error:  nil,
		}

		return c.JSON(http.StatusInternalServerError, res)
	}

	return c.Render(http.StatusOK, "tb-auth-test.html", authInfo)
}
