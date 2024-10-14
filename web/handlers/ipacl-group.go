package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-resty/resty/v2"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
	"github.com/yunkon-kim/knock-knock/internal/slack"
	"github.com/yunkon-kim/knock-knock/pkg/api/rest/model"
	"github.com/yunkon-kim/knock-knock/pkg/nhnutil"
)

func BindIpACLGroupToLoadBalancer(c echo.Context) error {
	id := c.Param("lb-id")
	if id == "" {
		errMsg := errors.New("empty loadbalancer ID").Error()
		log.Error().Msg(errMsg)
		return c.JSON(http.StatusBadRequest, model.BasicResponse{
			Result: "",
			Error:  &errMsg,
		})
	}

	// Path param, query param or reuqeust body
	ipaclGroupsBinding := new(nhnutil.IPACLGroupsBinding)
	if err := c.Bind(ipaclGroupsBinding); err != nil {
		log.Error().Err(err).Msg("")
		return c.JSON(http.StatusBadRequest, err)
	}
	log.Debug().Msgf("ipaclGroupsBinding: %v", ipaclGroupsBinding)

	token, err := getTokenFromSession(c)
	if err != nil {
		log.Error().Err(err).Msg("")
		return c.JSON(http.StatusInternalServerError, err)
	}

	name, err := getUsernameFromSession(c)
	if err != nil {
		log.Error().Err(err).Msg("")
		return c.JSON(http.StatusInternalServerError, err)
	}

	client := resty.New()
	apiURL := "http://localhost:8057/knock-knock/nhn/lbs/" + id + "/bind_ipacl_groups"

	// Get IP access control list targets (IP ACL targets)

	resp, err := client.R().
		SetHeader("Accept", "application/json").
		SetAuthToken(token).
		SetBody(ipaclGroupsBinding).
		Put(apiURL)

	if err != nil {
		log.Error().Err(err).Msg("failed to bind IP ACL Groups to the load balancer")
		return c.JSON(resp.StatusCode(), err)
	}

	if resp.IsError() {
		log.Error().Err(err).Msgf("API request failed with status code %d", resp.StatusCode())
		return c.JSON(resp.StatusCode(), err)
	}

	// Unmarshal response body
	pairList := new([]nhnutil.BoundPair)
	err = json.Unmarshal(resp.Body(), pairList)
	if err != nil {
		log.Error().Err(err).Msg("failed to unmarshal the bound IP ACL Groups to the load balancer")
		return c.JSON(http.StatusInternalServerError, err)
	}

	prettyJSON, err := json.MarshalIndent(pairList, "", "   ")
	if err != nil {
		log.Error().Err(err).Msgf("")
	}

	log.Trace().Msgf("pairList: %+v", string(prettyJSON))

	slack.PostMessage(
		"IP ACL groups are bound by " + name + " as follows.\n\n```" + string(prettyJSON) + "```")

	return c.JSON(http.StatusOK, pairList)
}

func CreateIpACLGroup(c echo.Context) error {

	// Path param, query param or reuqeust body
	ipACLGroup := new(nhnutil.IPACLGroup)
	if err := c.Bind(ipACLGroup); err != nil {
		log.Error().Err(err).Msg("")
		return c.JSON(http.StatusBadRequest, err)
	}
	log.Debug().Msgf("ipACLGroup: %v", ipACLGroup)

	token, err := getTokenFromSession(c)
	if err != nil {
		log.Error().Err(err).Msg("")
		return c.JSON(http.StatusUnauthorized, err)
	}

	name, err := getUsernameFromSession(c)
	if err != nil {
		log.Error().Err(err).Msg("")
		return c.JSON(http.StatusInternalServerError, err)
	}

	client := resty.New()
	apiURL := "http://localhost:8057/knock-knock/nhn/lbs/ipacl-groups"

	// Create IP access control list target (IP ACL target)
	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetAuthToken(token).
		SetBody(ipACLGroup).
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

	createdGroup := new(nhnutil.IPACLGroup)
	if err := json.Unmarshal(resp.Body(), createdGroup); err != nil {
		log.Error().Err(err).Msg("")
		return c.JSON(http.StatusInternalServerError, err)
	}

	prettyJSON, err := json.MarshalIndent(createdGroup, "", "   ")
	if err != nil {
		log.Error().Err(err).Msgf("")
		return c.JSON(http.StatusInternalServerError, err)
	}

	log.Debug().Msgf("createdGroup: %+v", createdGroup)

	slack.PostMessage(
		"IP ACL group is created by " + name + ".\n\n```" + string(prettyJSON) + "```")

	return c.JSON(http.StatusOK, createdGroup)
}

func DeleteIpACLGroup(c echo.Context) error {
	id := c.Param("ipacl-group-id")
	if id == "" {
		errMsg := errors.New("empty IP ACL group ID").Error()
		log.Error().Msg(errMsg)
		return c.JSON(http.StatusBadRequest, model.BasicResponse{
			Result: "",
			Error:  &errMsg,
		})
	}

	token, err := getTokenFromSession(c)
	if err != nil {
		log.Error().Err(err).Msg("")
		return c.JSON(http.StatusInternalServerError, err)
	}

	name, err := getUsernameFromSession(c)
	if err != nil {
		log.Error().Err(err).Msg("")
		return c.JSON(http.StatusInternalServerError, err)
	}

	client := resty.New()
	apiURL := "http://localhost:8057/knock-knock/nhn/lbs/ipacl-groups/" + id

	// Create IP access control list group (IP ACL group)
	resp, err := client.R().
		SetAuthToken(token).
		Delete(apiURL)

	if err != nil {
		log.Error().Err(err).Msg("")
		return c.JSON(http.StatusInternalServerError, err)
	}

	if err := nhnutil.CheckResponse(resp); err != nil {
		log.Error().Err(err).Msg("")
		return c.JSON(resp.StatusCode(), err)
	}

	slack.PostMessage(fmt.Sprintf("The IP ACL group (id: `%s`) is successfully deleted by %s.", id, name))

	res := model.BasicResponse{
		Result: "successfully deleted IP ACL group",
		Error:  nil,
	}

	return c.JSON(http.StatusOK, res)
}

func GetIpACLTarget(c echo.Context) error {

	id := c.Param("ipacl-group-id")
	if id == "" {
		errMsg := errors.New("empty IP ACL group ID").Error()
		log.Error().Msg(errMsg)
		return c.JSON(http.StatusBadRequest, model.BasicResponse{
			Result: "",
			Error:  &errMsg,
		})
	}

	token, err := getTokenFromSession(c)
	if err != nil {
		log.Error().Err(err).Msg("")
		return c.JSON(http.StatusInternalServerError, err)
	}

	client := resty.New()
	apiURL := "http://localhost:8057/knock-knock/nhn/lbs/ipacl-targets"

	// Get IP access control list targets (IP ACL targets)

	resp, err := client.R().
		SetHeader("Accept", "application/json").
		SetAuthToken(token).
		Get(apiURL)

	if err != nil {
		log.Error().Err(err).Msg("failed to get IP access control list targets (IP ACL targets)")
		return c.JSON(resp.StatusCode(), err)
	}

	if resp.IsError() {
		log.Error().Err(err).Msgf("API request failed with status code %d", resp.StatusCode())
		return c.JSON(resp.StatusCode(), err)
	}

	// Unmarshal response body
	ipaclTargets := new(nhnutil.IPACLTargets)
	err = json.Unmarshal(resp.Body(), ipaclTargets)
	if err != nil {
		log.Error().Err(err).Msg("failed to unmarshal IP access control list targets (IP ACL targets)")
		return c.JSON(http.StatusInternalServerError, err)
	}

	// Filter by ID (ipacl-group-id)
	ipaclTargets = filterIPACLTargets(ipaclTargets, id)

	prettyJSON, err := json.MarshalIndent(ipaclTargets, "", "   ")
	if err != nil {
		log.Error().Err(err).Msgf("")
	}

	log.Trace().Msgf("filltered IP ACL targets: %+v", string(prettyJSON))

	return c.JSON(http.StatusOK, ipaclTargets)
}

func filterIPACLTargets(ipaclTargets *nhnutil.IPACLTargets, groupId string) *nhnutil.IPACLTargets {

	filtered := new(nhnutil.IPACLTargets)
	for _, target := range ipaclTargets.IpaclTargets {
		if target.IpaclGroupId == groupId {
			filtered.IpaclTargets = append(filtered.IpaclTargets, target)
		}
	}

	return filtered
}

func CreateIpACLTarget(c echo.Context) error {

	// Path param, query param or reuqeust body
	ipACLTarget := new(nhnutil.IPACLTarget)
	if err := c.Bind(ipACLTarget); err != nil {
		log.Error().Err(err).Msg("")
		return c.JSON(http.StatusBadRequest, err)
	}
	log.Debug().Msgf("ipACLTarget: %v", ipACLTarget)

	token, err := getTokenFromSession(c)
	if err != nil {
		log.Error().Err(err).Msg("")
		return c.JSON(http.StatusInternalServerError, err)
	}

	name, err := getUsernameFromSession(c)
	if err != nil {
		log.Error().Err(err).Msg("")
		return c.JSON(http.StatusInternalServerError, err)
	}

	client := resty.New()
	apiURL := "http://localhost:8057/knock-knock/nhn/lbs/ipacl-targets"

	// Create IP access control list target (IP ACL target)
	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetAuthToken(token).
		SetBody(ipACLTarget).
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

	createdTarget := new(nhnutil.IPACLTarget)
	if err := json.Unmarshal(resp.Body(), createdTarget); err != nil {
		log.Error().Err(err).Msg("")
		return c.JSON(http.StatusInternalServerError, err)
	}

	prettyJSON, err := json.MarshalIndent(createdTarget, "", "   ")
	if err != nil {
		log.Error().Err(err).Msgf("")
	}

	log.Debug().Msgf("createdTarget: %+v", createdTarget)

	slack.PostMessage(
		"IP ACL target is created by " + name + ".\n\n```" + string(prettyJSON) + "```")

	return c.JSON(http.StatusOK, createdTarget)
}

func DeleteIpACLTarget(c echo.Context) error {

	// Path param, query param or reuqeust body
	id := c.Param("ipacl-target-id")
	if id == "" {
		log.Error().Msg("empty IP ACL target ID")
		return c.JSON(http.StatusBadRequest, "IP ACL target ID is required")
	}
	log.Debug().Msgf("IP ACL target ID: %s", id)

	token, err := getTokenFromSession(c)
	if err != nil {
		log.Error().Err(err).Msg("")
		return c.JSON(http.StatusInternalServerError, err)
	}

	name, err := getUsernameFromSession(c)
	if err != nil {
		log.Error().Err(err).Msg("")
		return c.JSON(http.StatusInternalServerError, err)
	}

	client := resty.New()
	apiURL := "http://localhost:8057/knock-knock/nhn/lbs/ipacl-targets/" + id

	// Create IP access control list target (IP ACL target)
	resp, err := client.R().
		SetAuthToken(token).
		Delete(apiURL)

	if err != nil {
		log.Error().Err(err).Msg("")
		return c.JSON(http.StatusInternalServerError, err)
	}

	if err := nhnutil.CheckResponse(resp); err != nil {
		log.Error().Err(err).Msg("")
		return c.JSON(resp.StatusCode(), err)
	}

	slack.PostMessage(fmt.Sprintf("The IP ACL target (id: `%s`) is successfully deleted by %s.", id, name))

	res := model.BasicResponse{
		Result: "successfully deleted IP ACL target",
		Error:  nil,
	}

	return c.JSON(http.StatusOK, res)
}
