package tumblebug

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
	"github.com/yunkon-kim/knock-knock/internal/config"
)

type tbIdList struct {
	IdList []string `json:"output"`
}

// RegionList is structure for region list
type tbRegionList struct {
	Regions []tbRegionDetail `mapstructure:"regions" json:"regions"`
}

// RegionDetail is structure for region information
type tbRegionDetail struct {
	RegionId    string     `mapstructure:"id" json:"regionId"`
	RegionName  string     `mapstructure:"regionName" json:"regionName"`
	Description string     `mapstructure:"description" json:"description"`
	Location    tbLocation `mapstructure:"location" json:"location"`
	Zones       []string   `mapstructure:"zone" json:"zones"`
}

// Location is structure for location information
type tbLocation struct {
	Display   string  `mapstructure:"display" json:"display"`
	Latitude  float64 `mapstructure:"latitude" json:"latitude"`
	Longitude float64 `mapstructure:"longitude" json:"longitude"`
}

func GetProviders() ([]string, error) {

	var emptyRet []string
	var providerList []string

	// [via Tumblebug] Get provider list
	client := resty.New()
	apiUser := config.Tumblebug.API.Username
	apiPass := config.Tumblebug.API.Password
	client.SetBasicAuth(apiUser, apiPass)

	tbRestEndpoint := config.Tumblebug.RestUrl
	// Set API URL
	url := fmt.Sprintf("%s/provider", tbRestEndpoint)

	// Set Resty
	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		Get(url)

	if err != nil {
		log.Error().Err(err).Msg("failed to get providers")
		return emptyRet, err
	}

	// Check response status code
	if resp.StatusCode() != http.StatusOK {
		log.Error().Msgf("failed to get providers (status code: %d)", resp.StatusCode())
		return emptyRet, fmt.Errorf("failed to get providers")
	}

	// Print result
	log.Debug().Msgf("Response Status Code: %d", resp.StatusCode())
	log.Trace().Msgf("Response Body: %s", resp.String())

	// Parse response
	var tbIdList tbIdList
	err = json.Unmarshal(resp.Body(), &tbIdList)
	if err != nil {
		log.Error().Err(err).Msg("failed to unmarshal response")
		return emptyRet, err
	}

	// Append provider list
	providerList = append(providerList, tbIdList.IdList...)

	return providerList, nil
}

func GetRegions(provider string) ([]string, error) {

	var emptyRet []string
	var regionList []string

	// [via Tumblebug] Get region list
	client := resty.New()
	apiUser := config.Tumblebug.API.Username
	apiPass := config.Tumblebug.API.Password
	client.SetBasicAuth(apiUser, apiPass)

	tbRestEndpoint := config.Tumblebug.RestUrl

	providerName := strings.ToLower(provider)

	// Set API URL
	url := fmt.Sprintf("%s/provider/%s/region", tbRestEndpoint, providerName)

	// Set Resty
	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		Get(url)

	if err != nil {
		log.Error().Err(err).Msgf("failed to get regions in provider (%s)", provider)
		return emptyRet, err
	}

	// Check response status code
	if resp.IsError() {
		err := fmt.Errorf("failed to get regions (status code: %d)", resp.StatusCode())
		log.Error().Err(err).Msg("")
		return emptyRet, err
	}

	// Print result
	log.Debug().Msgf("Response Status Code: %d", resp.StatusCode())
	log.Trace().Msgf("Response Body: %s", resp.String())

	// Parse response
	var tbRegionList tbRegionList
	err = json.Unmarshal(resp.Body(), &tbRegionList)
	if err != nil {
		log.Error().Err(err).Msg("failed to unmarshal response")
		return emptyRet, err
	}

	// Append region list
	for _, region := range tbRegionList.Regions {
		regionList = append(regionList, region.RegionId)
	}

	return regionList, nil
}
