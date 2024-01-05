package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-resty/resty/v2"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"

	_ "github.com/yunkon-kim/knock-knock/internal/logger"
	"github.com/yunkon-kim/knock-knock/pkg/api/rest/model"
	"github.com/yunkon-kim/knock-knock/pkg/nhnutil"
)

func CreateRule(c echo.Context) error {

	// Path param, query param or reuqeust body
	ruleData := new(nhnutil.SecurityGroupRule)
	if err := c.Bind(ruleData); err != nil {
		log.Error().Err(err).Msg("")
		return c.JSON(http.StatusBadRequest, err)
	}
	log.Debug().Msgf("ruleData: %v", ruleData)

	client := resty.New()

	// API endpoint
	apiURL := "http://localhost:8056/knock-knock/nhn/sgRule"

	// Create rule
	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(ruleData).
		Post(apiURL)

	if err != nil {
		log.Error().Err(err).Msg("")
		return c.JSON(http.StatusInternalServerError, err)
	}

	if err := nhnutil.CheckResponse(resp); err != nil {
		log.Error().Err(err).Msg("")
		return c.JSON(resp.StatusCode(), err)
	}

	log.Trace().Msgf("resp: %+v", resp)

	createdRule := new(nhnutil.SecurityGroupRule)
	if err := json.Unmarshal(resp.Body(), createdRule); err != nil {
		log.Error().Err(err).Msg("")
		return c.JSON(http.StatusInternalServerError, err)
	}

	log.Debug().Msgf("createdRule: %+v", createdRule)

	return c.JSON(http.StatusOK, createdRule)
}

func DeleteRule(c echo.Context) error {

	// Path param, query param or reuqeust body
	ruleID := c.Param("id")
	if ruleID == "" {
		log.Error().Msg("empty rule ID")
		return c.JSON(http.StatusBadRequest, "rule ID is required")
	}
	log.Debug().Msgf("ruleID: %s", ruleID)

	client := resty.New()

	// API endpoint
	apiURL := "http://localhost:8056/knock-knock/nhn/sgRule/" + ruleID

	// Delete rule
	resp, err := client.R().Delete(apiURL)

	if err != nil {
		log.Error().Err(err).Msg("")
		return c.JSON(http.StatusInternalServerError, err)
	}

	if err := nhnutil.CheckResponse(resp); err != nil {
		log.Error().Err(err).Msg("")
		return c.JSON(resp.StatusCode(), err)
	}

	res := model.BasicResponse{
		Result: "successfully deleted rule",
		Error:  nil,
	}

	return c.JSON(http.StatusOK, res)
}
