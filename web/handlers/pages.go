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
	apiURL := "http://localhost:8057/knock-knock/nhn/sg"

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

type LoadBalancers struct {
	LoadBalancers []LoadBalancerExt `json:"loadbalancers"`
}

type LoadBalancerExt struct {
	IpaclGroupAction   string             `json:"ipacl_group_action"`
	Description        string             `json:"description"`
	ProvisioningStatus string             `json:"provisioning_status"`
	TenantID           string             `json:"tenant_id"`
	Provider           string             `json:"provider"`
	IpaclGroups        []IPACLGroupExt    `json:"ipacl_groups"`
	Name               string             `json:"name"`
	LoadBalancerType   string             `json:"loadbalancer_type"`
	Listeners          []nhnutil.Listener `json:"listeners"`
	VipAddress         string             `json:"vip_address"`
	VipPortID          string             `json:"vip_port_id"`
	WorkflowStatus     string             `json:"workflow_status"`
	VipSubnetID        string             `json:"vip_subnet_id"`
	Id                 string             `json:"id"`
	OperatingStatus    string             `json:"operating_status"`
	AdminStateUp       bool               `json:"admin_state_up"`
}

type IPACLGroupExt struct {
	IpaclGroupId string `json:"ipacl_group_id,omitempty"`
	Description  string `json:"description,omitempty"`
	Checked      string `json:"checked,omitempty"`
}

func LoadBalancer(c echo.Context) error {

	token, err := getTokenFromSession(c)
	if err != nil {
		log.Error().Err(err).Msg("")
		return c.JSON(http.StatusInternalServerError, err)
	}

	client := resty.New()
	apiURL := "http://localhost:8057/knock-knock/nhn/lbs"

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
	lbs := new(LoadBalancers)
	err = json.Unmarshal(resp.Body(), lbs)
	if err != nil {
		log.Error().Err(err).Msg("failed to unmarshal load balancers")
		return err
	}

	// Get IP ACL groups
	apiURL = "http://localhost:8057/knock-knock/nhn/lbs/ipacl-groups"

	resp, err = client.R().
		SetHeader("Accept", "application/json").
		SetAuthToken(token).
		Get(apiURL)

	if err != nil {
		log.Error().Err(err).Msg("failed to get IP ACL groups")
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
		log.Error().Err(err).Msg("failed to unmarshal IP ACL groups")
		return err
	}

	// Improve each load balancer's IP ACL groups information
	for lbIdx, lb := range lbs.LoadBalancers {
		tempGroups := []IPACLGroupExt{}
		for _, ipaclGroup := range ipaclGroups.IpaclGroups {
			i := findGroupIndex(ipaclGroup.Id, lb.IpaclGroups)
			if i >= 0 {
				// Directly modify the original slice
				lbs.LoadBalancers[lbIdx].IpaclGroups[i].Description = ipaclGroup.Description
				lbs.LoadBalancers[lbIdx].IpaclGroups[i].Checked = "checked"
			} else {
				temp := IPACLGroupExt{
					IpaclGroupId: ipaclGroup.Id,
					Description:  ipaclGroup.Description,
					Checked:      "",
				}
				tempGroups = append(tempGroups, temp)
			}
		}
		// Append to the original slice
		lbs.LoadBalancers[lbIdx].IpaclGroups = append(lbs.LoadBalancers[lbIdx].IpaclGroups, tempGroups...)
	}
	log.Trace().Msgf("load balancers: %+v", lbs)

	return c.Render(http.StatusOK, "load-balancer.html", lbs)
}

func findGroupIndex(groupId string, ipaclGroups []IPACLGroupExt) int {
	for i, g := range ipaclGroups {
		if g.IpaclGroupId == groupId {
			return i
		}
	}
	return -1
}

func IpACLGroup(c echo.Context) error {

	token, err := getTokenFromSession(c)
	if err != nil {
		log.Error().Err(err).Msg("")
		return c.JSON(http.StatusInternalServerError, err)
	}

	client := resty.New()
	apiURL := "http://localhost:8057/knock-knock/nhn/lbs/ipacl-groups"

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
