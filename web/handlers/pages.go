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

func LoadBalancer(c echo.Context) error {

	token, err := getTokenFromSession(c)
	if err != nil {
		log.Error().Err(err).Msg("")
		return c.JSON(http.StatusInternalServerError, err)
	}

	client := resty.New()
	apiURL := "http://localhost:8056/knock-knock/nhn/lbs"

	// Get load balancers
	resp, err := client.R().
		SetHeader("Accept", "application/json").
		SetAuthToken(token).
		Get(apiURL)

	if err != nil {
		log.Error().Err(err).Msg("failed to get load balancers")
		return err
	}

	if resp.IsError() {
		log.Error().Err(err).Msgf("API request failed with status code %d", resp.StatusCode())
		return err
	}

	// Unmarshal response body
	lbs := new(nhnutil.LoadBalancers)
	err = json.Unmarshal(resp.Body(), lbs)
	if err != nil {
		log.Error().Err(err).Msg("failed to unmarshal load balancers")
		return err
	}

	return c.Render(http.StatusOK, "load-balancer.html", lbs)
}

func IpACLGroup(c echo.Context) error {

	token, err := getTokenFromSession(c)
	if err != nil {
		log.Error().Err(err).Msg("")
		return c.JSON(http.StatusInternalServerError, err)
	}

	client := resty.New()
	apiURL := "http://localhost:8056/knock-knock/nhn/lbs/ipacl-groups"

	// Get IP access control list groups (IP ACL groups)
	resp, err := client.R().
		SetHeader("Accept", "application/json").
		SetAuthToken(token).
		Get(apiURL)

	if err != nil {
		log.Error().Err(err).Msg("failed to get IP access control list groups (IP ACL groups)")
		return err
	}

	if resp.IsError() {
		log.Error().Err(err).Msgf("API request failed with status code %d", resp.StatusCode())
		return err
	}

	// Unmarshal response body
	ipaclGroups := new(nhnutil.IPACLGroups)
	err = json.Unmarshal(resp.Body(), ipaclGroups)
	if err != nil {
		log.Error().Err(err).Msg("failed to unmarshal IP access control list groups (IP ACL groups)")
		return err
	}

	return c.Render(http.StatusOK, "ip-acl-group.html", ipaclGroups)
}
