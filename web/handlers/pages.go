package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-resty/resty/v2"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
	"github.com/yunkon-kim/knock-knock/pkg/nhnutil"
)

func Dashboard(c echo.Context) error {
	return c.Render(http.StatusOK, "home.html", nil)
}

func SecurityGroup(c echo.Context) error {

	token, err := getTokenFromSession(c)
	if err != nil {
		log.Error().Err(err).Msg("")
		return c.JSON(http.StatusInternalServerError, err)
	}

	client := resty.New()
	apiURL := "http://localhost:8056/knock-knock/nhn/sg"

	// Get security groups
	resp, err := client.R().
		SetHeader("Accept", "application/json").
		SetAuthToken(token).
		Get(apiURL)

	if err != nil {
		log.Error().Err(err).Msg("failed to get security groups")
		return err
	}

	if resp.IsError() {
		log.Error().Err(err).Msgf("API request failed with status code %d", resp.StatusCode())
		return err
	}

	// Unmarshal response body
	sgList := new(nhnutil.SecurityGroups)
	err = json.Unmarshal(resp.Body(), sgList)
	if err != nil {
		log.Error().Err(err).Msg("failed to unmarshal security groups")
		return err
	}

	return c.Render(http.StatusOK, "security-group.html", sgList)
}
