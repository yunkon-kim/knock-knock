package controller

import (
	"encoding/json"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/yunkon-kim/knock-knock/pkg/api/rest/model"
	"github.com/yunkon-kim/knock-knock/pkg/nhnutil"

	// Black import (_) is for running a package's init() function without using its other contents.
	"github.com/rs/zerolog/log"
	_ "github.com/yunkon-kim/knock-knock/internal/config"
	_ "github.com/yunkon-kim/knock-knock/internal/logger"
)

// [Note]
// Struct Embedding is used to inherit the fields of nhnutil.AuthResponse
type GetTokenResponse struct {
	nhnutil.AuthResponse
}

// GetToken godoc
// @Summary Get a token
// @Description Get a token on NHN Cloud.
// @Tags [NHN Cloud] Token
// @Accept  json
// @Produce  json
// @Success 200 {object} GetTokenResponse "A token returned from NHN Cloud"
// @Failure 400 {object} object "Invalid Request"
// @Router /nhn/token [get]
func GetToken(c echo.Context) error {

	token, err := nhnutil.GetToken()

	if err != nil {
		log.Error().Err(err).Msg("Failed to get token")
		return c.JSON(http.StatusNotFound, err)
	}

	res := new(nhnutil.AuthResponse)

	err = json.Unmarshal([]byte(token), &res)
	if err != nil {
		log.Error().Err(err).Msg("Failed to unmarshal token")
		return c.JSON(http.StatusNotFound, err)
	}

	return c.JSON(http.StatusOK, res)
}

// [Note]
// Struct Embedding is used to inherit the fields of token ID
type SetTokenIdResponse struct {
	model.BasicResponse
}

// SetTokenId godoc
// @Summary Set a token ID
// @Description Set a token ID on NHN Cloud.
// @Tags [NHN Cloud] Token
// @Accept  json
// @Produce  json
// @Success 200 {object} SetTokenIdResponse "Result of setting token ID"
// @Failure 400 {object} object "Invalid Request"
// @Router /nhn/tokenId [post]
func SetTokenId(c echo.Context) error {

	err := nhnutil.SetTokenId()

	if err != nil {
		log.Error().Err(err).Msg("Failed to set token ID")
		return c.JSON(http.StatusNotFound, err)
	}

	return c.JSON(http.StatusOK, model.BasicResponse{
		Result: "Successfully set token ID",
		Error:  nil,
	})
}

// [Note]
// Struct Embedding is used to inherit the fields of security groups
type GetSecurityGroupsResponse struct {
	nhnutil.SecurityGroups
}

// GetSecurityGroups godoc
// @Summary Get a list of security groups
// @Description Get a list of security groups on NHN Cloud.
// @Tags [NHN Cloud] Security Group
// @Accept  json
// @Produce  json
// @Param  fields  query  string  false  "fields in security groups"
// @Success 200 {object} GetSecurityGroupsResponse "A list of security groups returned from NHN Cloud"
// @Failure 400 {object} model.BasicResponse "Bad Request"
// @Failure 401 {object} model.BasicResponse "Unauthorized"
// @Failure 404 {object} model.BasicResponse "Not Found"
// @Router /nhn/sg [get]
func GetSecurityGroups(c echo.Context) error {

	securityGroups, err := nhnutil.GetSecurityGroups(nhnutil.KR1)

	if err != nil {
		log.Error().Err(err).Msg("Failed to get security groups")
		errMsg := err.Error()
		if errMsg == "Authentication required" {
			return c.JSON(http.StatusUnauthorized, model.BasicResponse{
				Result: "Failed to get security groups",
				Error:  &errMsg,
			})
		}
		return c.JSON(http.StatusNotFound, model.BasicResponse{
			Result: "Failed to get security groups",
			Error:  &errMsg,
		})
	}

	res := new(nhnutil.SecurityGroups)

	err = json.Unmarshal([]byte(securityGroups), &res)
	if err != nil {
		log.Error().Err(err).Msg("Failed to unmarshal security groups")
		return c.JSON(http.StatusInternalServerError, err)
	}

	return c.JSON(http.StatusOK, res)
}

// Struct Embedding is used to inherit the fields of security group
type GetSecurityGroupResponse struct {
	SecurytiGroup nhnutil.SecurityGroup `json:"security_group"`
}

// GetSecurityGroup godoc
// @Summary Get a security group
// @Description Get a security groups on NHN Cloud.
// @Tags [NHN Cloud] Security Group
// @Accept  json
// @Produce  json
// @Param  id  path  string  true  "Security Group ID"
// @Success 200 {object} GetSecurityGroupResponse "A security groups returned from NHN Cloud"
// @Failure 400 {object} object "Invalid Request"
// @Router /nhn/sg/{id} [get]
func GetSecurityGroup(c echo.Context) error {

	sgId := c.Param("id")
	if sgId == "" {
		log.Error().Msg("Failed to get security group ID")
		err := "Failed to get security group ID"
		return c.JSON(http.StatusBadRequest, model.BasicResponse{
			Result: "",
			Error:  &err,
		})
	}

	log.Debug().Msgf("sgId: %s", sgId)

	securityGroups, err := nhnutil.GetSecurityGroup(nhnutil.KR1, sgId)

	if err != nil {
		log.Error().Err(err).Msg("Failed to get token ID")
		return c.JSON(http.StatusNotFound, err)
	}

	res := new(GetSecurityGroupResponse)

	err = json.Unmarshal([]byte(securityGroups), &res)
	if err != nil {
		log.Error().Err(err).Msg("Failed to unmarshal security groups")
		return c.JSON(http.StatusNotFound, err)
	}

	return c.JSON(http.StatusOK, res)
}
