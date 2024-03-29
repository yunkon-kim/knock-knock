package controller

import (
	"encoding/json"
	"errors"
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
// @Tags [NHN Cloud] Token (for dev and test)
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
// @Tags [NHN Cloud] Token (for dev and test)
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
// @Security Bearer
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
	nhnutil.SecurityGroup
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

// [Note]
// Struct Embedding is used to inherit the fields of security group rule
type AddSecurityGroupRuleRequest struct {
	nhnutil.SecurityGroupRule
}

// [Note]
// Struct Embedding is used to inherit the fields of security group rule
type AddSecurityGroupRuleResponse struct {
	nhnutil.SecurityGroupRule
}

// CreateSecurityGroupRule godoc
// @Summary Create a rule to security group
// @Description Create a rule to security group.
// @Tags [NHN Cloud] Security Group
// @Accept  json
// @Produce  json
// @Param  body  body  AddSecurityGroupRuleRequest  true  "Values to create a rule to security group"
// @Success 201 {object} AddSecurityGroupRuleResponse "Result of creating a rule to security group"
// @Failure 400 {object} model.BasicResponse "Bad Request"
// @Failure 401 {object} model.BasicResponse "Unauthorized"
// @Failure 404 {object} model.BasicResponse "Not Found"
// @Router /nhn/sgRule [post]
func CreateSecurityGroupRule(c echo.Context) error {

	// Get path params, query params and/or the request body
	req := new(nhnutil.SecurityGroupRule)
	if err := c.Bind(req); err != nil {
		log.Error().Err(err).Msg("")
		errMsg := err.Error()
		return c.JSON(http.StatusBadRequest, model.BasicResponse{
			Result: "",
			Error:  &errMsg,
		})
	}

	rule, err := nhnutil.CreateSecurityGroupRule(nhnutil.KR1, *req)
	if err != nil {
		log.Error().Err(err).Msg("")
		errMsg := err.Error()
		return c.JSON(http.StatusInternalServerError, model.BasicResponse{
			Result: "",
			Error:  &errMsg,
		})
	}

	createRule := new(AddSecurityGroupRuleResponse)
	err = json.Unmarshal([]byte(rule), &createRule)
	if err != nil {
		log.Error().Err(err).Msg("")
		errMsg := err.Error()
		return c.JSON(http.StatusInternalServerError, model.BasicResponse{
			Result: "",
			Error:  &errMsg,
		})
	}

	return c.JSON(http.StatusCreated, createRule)
}

// DeleteSecurityGroupRule godoc
// @Summary Delete a security group rule
// @Description Delete a security group rule.
// @Tags [NHN Cloud] Security Group
// @Accept  json
// @Produce  json
// @Param id path string true "a security group rule ID"
// @Success 200 {string} model.BasicResponse "Successfully deleted"
// @Failure 400 {object} model.BasicResponse "Bad Request"
// @Failure 401 {object} model.BasicResponse "Unauthorized"
// @Failure 404 {object} model.BasicResponse "Not Found"
// @Router /nhn/sgRule/{id} [delete]
func DeleteSecurityGroupRule(c echo.Context) error {
	id := c.Param("id")
	if id == "" {
		errMsg := errors.New("empty security group rule ID").Error()
		log.Error().Msg(errMsg)
		return c.JSON(http.StatusBadRequest, model.BasicResponse{
			Result: "",
			Error:  &errMsg,
		})
	}

	err := nhnutil.DeleteSecurityGroupRule(nhnutil.KR1, id)
	if err != nil {
		log.Error().Err(err).Msg("Failed to delete a security group rule")
		errMsg := err.Error()
		return c.JSON(http.StatusInternalServerError, model.BasicResponse{
			Result: "",
			Error:  &errMsg,
		})

	}

	return c.JSON(http.StatusOK, model.BasicResponse{
		Result: "successfully deleted a security group rule",
		Error:  nil,
	})
}

type GetNetworkACLsResponse struct {
	nhnutil.NetworkACLs
}

///////////////////////////////////////////////////////////////////////////////////////////////////////

// GetNetworkACLs godoc
// @Summary Get a list of network ACLs
// @Description Get a list of network ACLs on NHN Cloud.
// @Tags [NHN Cloud] Network ACL
// @Accept  json
// @Produce  json
// @Success 200 {object} GetNetworkACLsResponse "A list of network ACLs returned from NHN Cloud"
// @Failure 400 {object} model.BasicResponse "Bad Request"
// @Failure 401 {object} model.BasicResponse "Unauthorized"
// @Failure 404 {object} model.BasicResponse "Not Found"
// @Router /nhn/acls [get]
// @Security Bearer
func GetNetworkACLs(c echo.Context) error {

	acls, err := nhnutil.GetNetworkACLs(nhnutil.KR1)

	if err != nil {
		log.Error().Err(err).Msg("Failed to get network ACLs")
		errMsg := err.Error()
		if errMsg == "Authentication required" {
			return c.JSON(http.StatusUnauthorized, model.BasicResponse{
				Result: "Failed to get network ACLs",
				Error:  &errMsg,
			})
		}
		return c.JSON(http.StatusNotFound, model.BasicResponse{
			Result: "no network ACLs",
			Error:  &errMsg,
		})
	}

	res := new(nhnutil.NetworkACLs)

	err = json.Unmarshal([]byte(acls), &res)
	if err != nil {
		log.Error().Err(err).Msg("Failed to unmarshal network ACLs")
		errMsg := err.Error()
		return c.JSON(http.StatusInternalServerError, model.BasicResponse{
			Result: "Failed to unmarshal network ACLs",
			Error:  &errMsg,
		})
	}

	return c.JSON(http.StatusOK, res)
}

//////////////////////////////////////////////////////////////////////////////////

type GetLoadBalancersResponse struct {
	nhnutil.LoadBalancers
}

// GetLoadBalancers godoc
// @Summary Get a list of load balancers
// @Description Get a list of load balancers on NHN Cloud.
// @Tags [NHN Cloud] Load Balancer
// @Accept  json
// @Produce  json
// @Success 200 {object} GetLoadBalancersResponse "A list of load balancers returned from NHN Cloud"
// @Failure 400 {object} model.BasicResponse "Bad Request"
// @Failure 401 {object} model.BasicResponse "Unauthorized"
// @Failure 404 {object} model.BasicResponse "Not Found"
// @Router /nhn/lbs [get]
// @Security Bearer
func GetLoadBalancers(c echo.Context) error {

	lbs, err := nhnutil.GetLoadBalancers(nhnutil.KR1)

	if err != nil {
		log.Error().Err(err).Msg("Failed to get load balancers")
		errMsg := err.Error()
		if errMsg == "Authentication required" {
			return c.JSON(http.StatusUnauthorized, model.BasicResponse{
				Result: "Failed to get load balancers",
				Error:  &errMsg,
			})
		}
		return c.JSON(http.StatusNotFound, model.BasicResponse{
			Result: "no load balancers",
			Error:  &errMsg,
		})
	}

	res := new(nhnutil.LoadBalancers)

	err = json.Unmarshal([]byte(lbs), &res)
	if err != nil {
		log.Error().Err(err).Msg("Failed to unmarshal load balancers")
		errMsg := err.Error()
		return c.JSON(http.StatusInternalServerError, model.BasicResponse{
			Result: "Failed to unmarshal load balancers",
			Error:  &errMsg,
		})
	}

	return c.JSON(http.StatusOK, res)
}

type BindIpACLGroupToLoadBalancerRequest struct {
	nhnutil.IPACLGroupsBinding
}

// BindIpACLGroupToLoadBalancer godoc
// @Summary Bind an IP access control list group (IP ACL group) to a load balancer
// @Description Bind an IP access control list group (IP ACL group) to a load balancer on NHN Cloud.
// @Tags [NHN Cloud] Load Balancer
// @Accept  json
// @Produce  json
// @Param  id  path  string  true  "Load Balancer ID"
// @Param  body  body  string  true  "IP access control list group ID"
// @Success 200 {object} []nhnutil.BoundPair "Successfully binded"
// @Failure 400 {object} model.BasicResponse "Bad Request"
// @Failure 401 {object} model.BasicResponse "Unauthorized"
// @Failure 404 {object} model.BasicResponse "Not Found"
// @Router /nhn/lbs/{id}/bind_ipacl_groups [put]
// @Security Bearer
func BindIpACLGroupToLoadBalancer(c echo.Context) error {

	id := c.Param("id")
	if id == "" {
		errMsg := errors.New("empty ID of load balancer").Error()
		log.Error().Msg(errMsg)
		return c.JSON(http.StatusBadRequest, model.BasicResponse{
			Result: "",
			Error:  &errMsg,
		})
	}

	// Get path params, query params and/or the request body
	req := new(nhnutil.IPACLGroupsBinding)
	if err := c.Bind(req); err != nil {
		log.Error().Err(err).Msg("")
		errMsg := err.Error()
		return c.JSON(http.StatusBadRequest, model.BasicResponse{
			Result: "",
			Error:  &errMsg,
		})
	}

	pairList, err := nhnutil.BindIpACLGroupToLoadBalancer(nhnutil.KR1, id, *req)
	if err != nil {
		log.Error().Err(err).Msg("Failed to bind an IP ACL groups to a load balancer")
		errMsg := err.Error()
		return c.JSON(http.StatusInternalServerError, model.BasicResponse{
			Result: "",
			Error:  &errMsg,
		})
	}

	res := new([]nhnutil.BoundPair)

	err = json.Unmarshal([]byte(pairList), &res)
	if err != nil {
		log.Error().Err(err).Msg("Failed to unmarshal a list of the bound IP ACL groups to a load balancer")
		errMsg := err.Error()
		return c.JSON(http.StatusInternalServerError, model.BasicResponse{
			Result: "Failed to unmarshal a list of the bound IP ACL groups to a load balancer",
			Error:  &errMsg,
		})
	}

	return c.JSON(http.StatusOK, res)
}

// ////////////////////////////////////////////////////////////////////////////////
type GetIpACLGroupsResponse struct {
	nhnutil.IPACLGroups
}

// GetIpACLGroups godoc
// @Summary Get IP access control list groups (IP ACL groups)
// @Description Get access control list groups (IP ACL groups) on NHN Cloud.
// @Tags [NHN Cloud] Load Balancer
// @Accept  json
// @Produce  json
// @Success 200 {object} GetIpACLGroupsResponse "Access control list groups (IP ACL groups) from NHN Cloud"
// @Failure 400 {object} model.BasicResponse "Bad Request"
// @Failure 401 {object} model.BasicResponse "Unauthorized"
// @Failure 404 {object} model.BasicResponse "Not Found"
// @Router /nhn/lbs/ipacl-groups [get]
// @Security Bearer
func GetIpACLGroups(c echo.Context) error {

	ipacls, err := nhnutil.GetIpACLGroups(nhnutil.KR1)

	if err != nil {
		log.Error().Err(err).Msg("Failed to get IP access control list groups (IP ACL groups)")
		errMsg := err.Error()
		if errMsg == "Authentication required" {
			return c.JSON(http.StatusUnauthorized, model.BasicResponse{
				Result: "Failed to get IP access control list groups (IP ACL groups)",
				Error:  &errMsg,
			})
		}
		return c.JSON(http.StatusNotFound, model.BasicResponse{
			Result: "no IP access control list groups (IP ACL groups)",
			Error:  &errMsg,
		})
	}

	res := new(nhnutil.IPACLGroups)

	err = json.Unmarshal([]byte(ipacls), &res)
	if err != nil {
		log.Error().Err(err).Msg("Failed to unmarshal IP access control groups (IP ACL groups)")
		errMsg := err.Error()
		return c.JSON(http.StatusInternalServerError, model.BasicResponse{
			Result: "Failed to unmarshal IP access control groups (IP ACL groups)",
			Error:  &errMsg,
		})
	}

	return c.JSON(http.StatusOK, res)
}

type CreateIpACLGroupRequest struct {
	nhnutil.IPACLGroup
}

type CreateIpACLGroupResponse struct {
	nhnutil.IPACLGroup
}

// CreateIpACLGroup godoc
// @Summary Create an IP access control list group (IP ACL group)
// @Description Create an access control list group (IP ACL group) on NHN Cloud.
// @Tags [NHN Cloud] Load Balancer
// @Accept  json
// @Produce  json
// @Success 200 {object} CreateIpACLGroupResponse "An access control list group (IP ACL group) from NHN Cloud"
// @Failure 400 {object} model.BasicResponse "Bad Request"
// @Failure 401 {object} model.BasicResponse "Unauthorized"
// @Failure 404 {object} model.BasicResponse "Not Found"
// @Router /nhn/lbs/ipacl-groups [post]
// @Security Bearer
func CreateIpACLGroup(c echo.Context) error {

	// Get path params, query params and/or the request body
	req := new(nhnutil.IPACLGroup)
	if err := c.Bind(req); err != nil {
		log.Error().Err(err).Msg("")
		errMsg := err.Error()
		return c.JSON(http.StatusBadRequest, model.BasicResponse{
			Result: "",
			Error:  &errMsg,
		})
	}

	ipaclGroup, err := nhnutil.CreateIpACLGroup(nhnutil.KR1, *req)

	if err != nil {
		log.Error().Err(err).Msg("Failed to create an IP access control list group (IP ACL group)")
		errMsg := err.Error()
		if errMsg == "Authentication required" {
			return c.JSON(http.StatusUnauthorized, model.BasicResponse{
				Result: "Failed to create an IP access control list group (IP ACL group)",
				Error:  &errMsg,
			})
		}
	}

	res := new(nhnutil.IPACLGroup)

	err = json.Unmarshal([]byte(ipaclGroup), &res)
	if err != nil {
		log.Error().Err(err).Msg("Failed to unmarshal an IP access control list group (IP ACL group)")
		errMsg := err.Error()
		return c.JSON(http.StatusInternalServerError, model.BasicResponse{
			Result: "Failed to unmarshal an IP access control list group (IP ACL group)",
			Error:  &errMsg,
		})
	}

	return c.JSON(http.StatusOK, res)
}

// DeleteIpACLGroup godoc
// @Summary Delete an IP access control list group (IP ACL group)
// @Description Delete an IP access control list group (IP ACL group) on NHN Cloud.
// @Tags [NHN Cloud] Load Balancer
// @Accept  json
// @Produce  json
// @Failure 400 {object} model.BasicResponse "Bad Request"
// @Failure 401 {object} model.BasicResponse "Unauthorized"
// @Failure 404 {object} model.BasicResponse "Not Found"
// @Router /nhn/lbs/ipacl-groups/{id} [delete]
// @Security Bearer
func DeleteIpACLGroup(c echo.Context) error {

	id := c.Param("id")
	if id == "" {
		errMsg := errors.New("empty IF of IP access control list group (ACL group)").Error()
		log.Error().Msg(errMsg)
		return c.JSON(http.StatusBadRequest, model.BasicResponse{
			Result: "",
			Error:  &errMsg,
		})
	}

	err := nhnutil.DeleteIpACLGroup(nhnutil.KR1, id)
	if err != nil {
		log.Error().Err(err).Msg("Failed to delete IP access control list group (ACL group)")
		errMsg := err.Error()
		return c.JSON(http.StatusInternalServerError, model.BasicResponse{
			Result: "",
			Error:  &errMsg,
		})
	}

	return c.JSON(http.StatusOK, model.BasicResponse{
		Result: "successfully deleted IP access control list group (ACL group)",
		Error:  nil,
	})
}

type GetIpACLTargetsResponse struct {
	nhnutil.IPACLTargets
}

// GetIpACLTargets godoc
// @Summary Get IP access control list targets (IP ACL targets)
// @Description Get access control list targets (IP ACL targets) on NHN Cloud.
// @Tags [NHN Cloud] Load Balancer
// @Accept  json
// @Produce  json
// @Success 200 {object} GetIpACLTargetsResponse "Access control list targets (IP ACL targets) from NHN Cloud"
// @Failure 400 {object} model.BasicResponse "Bad Request"
// @Failure 401 {object} model.BasicResponse "Unauthorized"
// @Failure 404 {object} model.BasicResponse "Not Found"
// @Router /nhn/lbs/ipacl-targets [get]
// @Security Bearer
func GetIpACLTargets(c echo.Context) error {

	ipaclTargets, err := nhnutil.GetIpACLTargets(nhnutil.KR1)

	if err != nil {
		log.Error().Err(err).Msg("Failed to get IP access control list targets (IP ACL targets)")
		errMsg := err.Error()
		if errMsg == "Authentication required" {
			return c.JSON(http.StatusUnauthorized, model.BasicResponse{
				Result: "Failed to get IP access control list targets (IP ACL targets)",
				Error:  &errMsg,
			})
		}
		return c.JSON(http.StatusNotFound, model.BasicResponse{
			Result: "no IP access control list targets (IP ACL targets)",
			Error:  &errMsg,
		})
	}

	res := new(nhnutil.IPACLTargets)

	err = json.Unmarshal([]byte(ipaclTargets), &res)
	if err != nil {
		log.Error().Err(err).Msg("Failed to unmarshal IP access control targets (IP ACL targets)")
		errMsg := err.Error()
		return c.JSON(http.StatusInternalServerError, model.BasicResponse{
			Result: "Failed to unmarshal IP access control targets (IP ACL targets)",
			Error:  &errMsg,
		})
	}

	return c.JSON(http.StatusOK, res)
}

type CreateIpACLTargetRequest struct {
	nhnutil.IPACLTarget
}

type CreateIpACLTargetResponse struct {
	nhnutil.IPACLTarget
}

// CreateIpACLTarget godoc
// @Summary Create an IP access control list target (IP ACL target)
// @Description Create an access control list target (IP ACL target) on NHN Cloud.
// @Tags [NHN Cloud] Load Balancer
// @Accept  json
// @Produce  json
// @Success 200 {object} CreateIpACLTargetResponse "An access control list target (IP ACL target) from NHN Cloud"
// @Failure 400 {object} model.BasicResponse "Bad Request"
// @Failure 401 {object} model.BasicResponse "Unauthorized"
// @Failure 404 {object} model.BasicResponse "Not Found"
// @Router /nhn/lbs/ipacl-targets [post]
// @Security Bearer
func CreateIpACLTarget(c echo.Context) error {

	// Get path params, query params and/or the request body
	req := new(nhnutil.IPACLTarget)
	if err := c.Bind(req); err != nil {
		log.Error().Err(err).Msg("")
		errMsg := err.Error()
		return c.JSON(http.StatusBadRequest, model.BasicResponse{
			Result: "",
			Error:  &errMsg,
		})
	}

	ipaclTarget, err := nhnutil.CreateIpACLTarget(nhnutil.KR1, *req)

	if err != nil {
		log.Error().Err(err).Msg("Failed to create an IP access control list target (IP ACL target)")
		errMsg := err.Error()
		if errMsg == "Authentication required" {
			return c.JSON(http.StatusUnauthorized, model.BasicResponse{
				Result: "Failed to create an IP access control list target (IP ACL target)",
				Error:  &errMsg,
			})
		}
	}

	res := new(nhnutil.IPACLTarget)

	err = json.Unmarshal([]byte(ipaclTarget), &res)
	if err != nil {
		log.Error().Err(err).Msg("Failed to unmarshal an IP access control list target (IP ACL target)")
		errMsg := err.Error()
		return c.JSON(http.StatusInternalServerError, model.BasicResponse{
			Result: "Failed to unmarshal an IP access control list target (IP ACL target)",
			Error:  &errMsg,
		})
	}

	return c.JSON(http.StatusOK, res)
}

// DeleteIpACLTarget godoc
// @Summary Delete an IP access control list target (IP ACL target)
// @Description Delete an IP access control list target (IP ACL target) on NHN Cloud.
// @Tags [NHN Cloud] Load Balancer
// @Accept  json
// @Produce  json
// @Failure 400 {object} model.BasicResponse "Bad Request"
// @Failure 401 {object} model.BasicResponse "Unauthorized"
// @Failure 404 {object} model.BasicResponse "Not Found"
// @Router /nhn/lbs/ipacl-targets/{id} [delete]
// @Security Bearer
func DeleteIpACLTarget(c echo.Context) error {

	id := c.Param("id")
	if id == "" {
		errMsg := errors.New("empty IF of IP access control list target (ACL target)").Error()
		log.Error().Msg(errMsg)
		return c.JSON(http.StatusBadRequest, model.BasicResponse{
			Result: "",
			Error:  &errMsg,
		})
	}

	err := nhnutil.DeleteIpACLTarget(nhnutil.KR1, id)
	if err != nil {
		log.Error().Err(err).Msg("Failed to delete IP access control list target (ACL target)")
		errMsg := err.Error()
		return c.JSON(http.StatusInternalServerError, model.BasicResponse{
			Result: "",
			Error:  &errMsg,
		})
	}

	return c.JSON(http.StatusOK, model.BasicResponse{
		Result: "successfully deleted IP access control list target (ACL target)",
		Error:  nil,
	})
}

// // Struct Embedding is used to inherit the fields of security group
// type UpdateSecurityGroupRequest struct {
// 	SecurityGroupdId    string `json:"security_group_id"`
// 	SecurityGroupRuleId string `json:"security_group_rule_id"`
// 	Username            string `json:"username"`
// 	RemoteIpPrefix      string `json:"remote_ip_prefix"`
// }

// // Struct Embedding is used to inherit the fields of security group
// type UpdateSecurityGroupResponse struct {
// 	nhnutil.SecurityGroup
// }

// // UpdateSecurityGroup godoc
// // @Summary Update a security group
// // @Description Update a security groups on NHN Cloud.
// // @Tags [NHN Cloud] Security Group
// // @Accept  json
// // @Produce  json
// // @Param  id  path  string  true  "Security Group ID"
// // @Param  body  body  UpdateSecurityGroupRequest  true  "Values to update a security group"
// // @Success 200 {object} UpdateSecurityGroupResponse "A security groups returned from NHN Cloud"
// // @Failure 400 {object} object "Invalid Request"
// // @Router /nhn/sg/{id} [put]
// func UpdateSecurityGroup(c echo.Context) error {

// 	// Get path params, query params and/or the request body
// 	sgId := c.Param("id")
// 	if sgId == "" {
// 		log.Error().Msg("Failed to get security group ID")
// 		err := "Failed to get security group ID"
// 		return c.JSON(http.StatusBadRequest, model.BasicResponse{
// 			Result: "",
// 			Error:  &err,
// 		})
// 	}
// 	log.Debug().Msgf("sgId: %s", sgId)

// 	req := new(UpdateSecurityGroupRequest)
// 	if err := c.Bind(req); err != nil {
// 		log.Error().Err(err).Msg("Failed to bind request")
// 		return c.JSON(http.StatusBadRequest, "Invalid request")
// 	}
// 	log.Debug().Msgf("req: %v", req)

// 	// Get the security group
// 	sgStr, err := nhnutil.GetSecurityGroup(nhnutil.KR1, sgId)
// 	if err != nil {
// 		log.Error().Err(err).Msgf("Failed to get the security group (id: %s)", sgId)
// 		return c.JSON(http.StatusNotFound, err)
// 	}
// 	log.Debug().Msgf("securityGroup: %s", sgStr)

// 	sg := new(nhnutil.SecurityGroup)
// 	err = json.Unmarshal([]byte(sgStr), sg)
// 	if err != nil {
// 		log.Error().Err(err).Msg("Failed to unmarshal security groups")
// 		return c.JSON(http.StatusInternalServerError, err)
// 	}
// 	log.Debug().Msgf("sg: %+v", sg)

// 	// Update the security group rule
// 	rule := nhnutil.SecurityGroupRule{
// 		Id:             req.SecurityGroupRuleId,
// 		Description:    req.Username,
// 		RemoteIpPrefix: req.RemoteIpPrefix,
// 	}

// 	log.Debug().Msgf("rule: %+v", rule)

// 	updated, err := nhnutil.UpdateSecurityGroupRule(*sg, rule)
// 	if err != nil {
// 		log.Error().Err(err).Msg("Failed to update the security group rule")
// 		return c.JSON(http.StatusInternalServerError, err)
// 	}
// 	log.Debug().Msgf("rule-updated sg: %+v", updated)

// 	// Remove tenant_id which is read-only
// 	err = setFieldToEmptyString(&updated, "TenantId")
// 	if err != nil {
// 		log.Error().Err(err).Msg("Failed to set TenantId to an empty string")
// 		return c.JSON(http.StatusInternalServerError, err)
// 	}
// 	log.Debug().Msgf("TenantId-omitted sg: %+v", updated)

// 	// Update the security group
// 	updateResult, err := nhnutil.UpdateSecurityGroup(nhnutil.KR1, sgId, updated)
// 	if err != nil {
// 		log.Error().Err(err).Msg("Failed to update the security group")
// 		return c.JSON(http.StatusInternalServerError, err)
// 	}
// 	log.Debug().Msgf("result: %+v", updateResult)

// 	return c.JSON(http.StatusOK, updateResult)
// }

// // setFieldToEmptyString sets the field with the given name to an empty string
// // in a struct, if the field exists and is of type string.
// func setFieldToEmptyString(v interface{}, fieldName string) error {
// 	rv := reflect.ValueOf(v)

// 	// Ensure we are working with a struct or a pointer to a struct
// 	if rv.Kind() == reflect.Ptr {
// 		rv = rv.Elem()
// 	}

// 	if rv.Kind() != reflect.Struct {
// 		return fmt.Errorf("expected a struct or pointer to a struct, got %s", rv.Kind())
// 	}

// 	for i := 0; i < rv.NumField(); i++ {
// 		field := rv.Field(i)

// 		// Check if this is the field we're looking for
// 		if field.Kind() == reflect.String && rv.Type().Field(i).Name == fieldName {
// 			fmt.Printf("Setting empty string for field %s\n", rv.Type().Field(i).Name)
// 			field.SetString("")
// 		}

// 		// If the field is a struct or a pointer to a struct, recurse into it
// 		if field.Kind() == reflect.Struct || (field.Kind() == reflect.Ptr && field.Elem().Kind() == reflect.Struct) {
// 			fmt.Printf("Recursing into field %s\n", rv.Type().Field(i).Name)
// 			err := setFieldToEmptyString(field.Addr().Interface(), fieldName)
// 			if err != nil {
// 				return err
// 			}
// 		}
// 	}

// 	return nil
// }
