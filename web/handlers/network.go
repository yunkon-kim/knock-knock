package handlers

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
	"github.com/yunkon-kim/knock-knock/pkg/tumblebug"
)

func ViewNetworkDesign(c echo.Context) error {

	token, err := getTokenFromSession(c)
	if err != nil {
		log.Error().Err(err).Msg("")
		return c.JSON(http.StatusInternalServerError, err)
	}

	log.Debug().Msgf("token: %v", token)

	// map to store csp and regions
	// e.g., cspRegions["AWS"] = []string{"us-east-1", "us-west-2", "eu-central-1", "ap-northeast-2"}
	cspRegions := make(map[string][]string)

	providers, err := tumblebug.GetProviders()
	if err != nil {
		log.Error().Err(err).Msg("")
		return c.JSON(http.StatusInternalServerError, err)
	}

	for _, provider := range providers {
		log.Debug().Msgf("provider: %v", provider)

		regions, err := tumblebug.GetRegions(provider)
		if err != nil {
			log.Error().Err(err).Msg("")
			continue
		}

		cspRegions[provider] = regions
	}

	return c.Render(http.StatusOK, "net.html", map[string]interface{}{
		"cspRegions": cspRegions,
	})
}
