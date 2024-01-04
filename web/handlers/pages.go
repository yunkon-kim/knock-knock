package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
	"github.com/yunkon-kim/knock-knock/pkg/nhnutil"
)

func Dashboard(c echo.Context) error {
	return c.Render(http.StatusOK, "home.html", nil)
}

func SecurityGroup(c echo.Context) error {

	sgListStr, err := nhnutil.GetSecurityGroups(nhnutil.KR1)
	if err != nil {
		log.Error().Err(err).Msg("failed to get security groups")
		return err
	}

	sgList := new(nhnutil.SecurityGroups)
	err = json.Unmarshal([]byte(sgListStr), sgList)
	if err != nil {
		log.Error().Err(err).Msg("failed to unmarshal security groups")
		return err
	}

	return c.Render(http.StatusOK, "security-group.html", sgList)
}
