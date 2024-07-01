package controller

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-resty/resty/v2"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
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

// TbAuthTest godoc
// @Summary Auth test with TB.
// @Description Auth test with TB.
// @Tags [Auth] Test with TB
// @Accept  json
// @Produce  json
// @Success 200 {object} AuthsInfo "Auth info for test"
// @Failure 400 {object} model.BasicResponse "Bad Request"
// @Failure 401 {object} model.BasicResponse "Unauthorized"
// @Failure 404 {object} model.BasicResponse "Not Found"
// @Router /tb/auth/test [get]
// @Security Bearer
func TbAuthTest(c echo.Context) error {

	client := resty.New()

	apiEndpoint := "http://localhost:1323"
	// Set API URL
	urlTbAuthTest := fmt.Sprintf("%s/tumblebug/auth/test", apiEndpoint)

	token := c.Get("token").(string)
	if token == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "Token is required")
	}

	log.Debug().Msgf("token: %v", token)

	// Set Resty
	resp, err := client.R().
		SetHeader("Authorization", "Bearer "+token).
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

	res := authInfo

	return c.JSON(http.StatusOK, res)

}
