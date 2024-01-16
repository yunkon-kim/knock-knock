package nhnutil

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-resty/resty/v2"
	"github.com/spf13/viper"

	// Black import (_) is for running a package's init() function without using its other contents.
	"github.com/rs/zerolog/log"
	_ "github.com/yunkon-kim/knock-knock/internal/config"
	_ "github.com/yunkon-kim/knock-knock/internal/logger"
)

const (
	filenameSecurityGroup       = "security_group.tf"
	filenameAttachSecurityGroup = "attach_security_group.tf"
)

// Define type for region
type Region string

// Define const for region
const (
	KR1 Region = "kr1"
	KR2 Region = "kr2"
	KR3 Region = "jp1"
)

// Define type for resource type
type ResourceType string

// Define const for resource type
const (
	Instance    ResourceType = "instance"
	Network     ResourceType = "network"
	Image       ResourceType = "image"
	Volumev2    ResourceType = "block-storage"
	ObjectStore ResourceType = "object-storage"
	KeyManager  ResourceType = "key-manager"
)

// POST /v2.0/tokens - request body
type TokenRequest struct {
	Auth Auth `json:"auth"`
}
type Auth struct {
	TenantId            string              `json:"tenantId"`
	PasswordCredentials PasswordCredentials `json:"passwordCredentials"`
}

type PasswordCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// POST /v2.0/tokens - response body
type AuthResponse struct {
	Access Access `json:"access"`
}

type Access struct {
	Token          Token            `json:"token"`
	ServiceCatalog []ServiceCatalog `json:"serviceCatalog"`
	User           User             `json:"user"`
	Metadata       Metadata         `json:"metadata"`
}

type Token struct {
	ID       string `json:"id"`
	Expires  string `json:"expires"`
	Tenant   Tenant `json:"tenant"`
	IssuedAt string `json:"issued_at"`
}

type Tenant struct {
	ID                    string `json:"id"`
	Name                  string `json:"name"`
	GroupID               string `json:"groupId"`
	Description           string `json:"description"`
	Enabled               bool   `json:"enabled"`
	ProjectDomain         string `json:"project_domain"`
	RegionOneSDNPreferred string `json:"RegionOne_sdn_preferred"`
}

type ServiceCatalog struct {
	Endpoints []Endpoint `json:"endpoints"`
	Type      string     `json:"type"`
	Name      string     `json:"name"`
}

type Endpoint struct {
	PublicURL string `json:"publicURL"`
	Region    string `json:"region"`
}

type User struct {
	ID         string     `json:"id"`
	Username   string     `json:"username"`
	Name       string     `json:"name"`
	Roles      []Role     `json:"roles"`
	RolesLinks []RoleLink `json:"roles_links"`
}
type Role struct {
	Name string `json:"name"`
}
type RoleLink struct {
}

type Metadata struct {
	Roles   []string `json:"roles"`
	IsAdmin int      `json:"is_admin"`
}

// Get /v2.0/security-groups - response body
type SecurityGroups struct {
	SecurityGroups []SecurityGroupDetails `json:"security_groups"`
}

type SecurityGroup struct {
	SecurityGroup SecurityGroupDetails `json:"security_group"`
}

type SecurityGroupDetails struct {
	TenantId           string                     `json:"tenant_id,omitempty"`
	Description        string                     `json:"description"`
	Id                 string                     `json:"id"`
	SecurityGroupRules []SecurityGroupRuleDetails `json:"security_group_rules"`
	Name               string                     `json:"name"`
}

type SecurityGroupRule struct {
	SecurityGroupRule SecurityGroupRuleDetailsExt `json:"security_group_rule"`
}

type SecurityGroupRuleDetails struct {
	Direction       string  `json:"direction" default:"ingress"`
	Protocol        string  `json:"protocol" default:"tcp"`
	Description     string  `json:"description"`
	PortRangeMax    int     `json:"port_range_max"`
	Id              string  `json:"id,omitempty"`
	RemoteGroupId   *string `json:"remote_group_id,omitempty"`
	RemoteIpPrefix  string  `json:"remote_ip_prefix"`
	SecurityGroupId string  `json:"security_group_id"`
	TenantId        string  `json:"tenant_id,omitempty"`
	PortRangeMin    int     `json:"port_range_min"`
	Ethertype       string  `json:"ethertype"`
}

type SecurityGroupRuleDetailsExt struct {
	Direction       string `json:"direction" default:"ingress"`
	Protocol        string `json:"protocol" default:"tcp"`
	Description     string `json:"description"`
	PortRangeMax    int    `json:"port_range_max"`
	Id              string `json:"id,omitempty"`
	RemoteGroupId   string `json:"remote_group_id,omitempty"`
	RemoteIpPrefix  string `json:"remote_ip_prefix"`
	SecurityGroupId string `json:"security_group_id"`
	TenantId        string `json:"tenant_id,omitempty"`
	PortRangeMin    int    `json:"port_range_min"`
	Ethertype       string `json:"ethertype"`
	UpdatedAt       string `json:"updated_at,omitempty"`
	RevisionNumber  int    `json:"revision_number,omitempty"`
	CreatedAt       string `json:"created_at,omitempty"`
	ProjectId       string `json:"project_id,omitempty"`
}

var (
	apiEndpointIdentity                = "https://api-identity-infrastructure.nhncloudservice.com"
	apiEndpointInfrastructureDocstring = `https://%s-api-%s-infrastructure.nhncloudservice.com`
	apiEndpointVolumev2Docstring       = `https://%s-api-object-storage.nhncloudservice.com`
	tenantId                           string
	username                           string
	apiPassword                        string
	tokenId                            = ""
)

func init() {
	tenantId = viper.GetString("nhncloud.tenantId")
	if tenantId == "" {
		log.Fatal().Msg("tenantId is not set in config file or environment variable")
	}
	username = viper.GetString("nhncloud.username")
	if username == "" {
		log.Fatal().Msg("username is not set in config file or environment variable")
	}
	apiPassword = viper.GetString("nhncloud.apiPassword")
	if apiPassword == "" {
		log.Fatal().Msg("apiPassword is not set in config file or environment variable")
	}

	// Set token ID
	SetTokenId()
}

func CheckResponse(resp *resty.Response) error {
	if resp.StatusCode() < http.StatusOK || resp.StatusCode() >= http.StatusMultipleChoices {
		errMsg := fmt.Sprintf("API call failed with status code: %d, body: %s", resp.StatusCode(), resp.String())
		log.Error().Msg(errMsg)
		return errors.New(errMsg)
	}
	return nil
}

func GetToken() (string, error) {
	client := resty.New()

	// Set API URL for getting token
	urlToken := fmt.Sprintf("%s/v2.0/tokens", apiEndpointIdentity)

	// Set request body
	req := TokenRequest{
		Auth: Auth{
			TenantId: tenantId,
			PasswordCredentials: PasswordCredentials{
				Username: username,
				Password: apiPassword,
			},
		},
	}

	reqJsonBytes, err := json.Marshal(req)
	log.Debug().Msgf("Request Body: %s", reqJsonBytes)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal JSON")
		return "", err
	}

	// Set Resty
	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(reqJsonBytes).
		Post(urlToken)

	if err != nil {
		return "", err
	}
	if err := CheckResponse(resp); err != nil {
		return "", err
	}

	log.Info().Msg("Successfully got token")
	log.Debug().Msgf("Response Status Code: %d", resp.StatusCode())
	log.Debug().Msgf("Response Body: %s", resp.String())

	return resp.String(), nil
}

func GetTokenId() (string, error) {

	token, err := GetToken()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get token")
		return "", err
	}

	// Parse JSON
	var authResponse AuthResponse
	err = json.Unmarshal([]byte(token), &authResponse)
	if err != nil {
		log.Error().Err(err).Msg("Failed to parse JSON")
		return "", err
	}
	log.Debug().Msgf("Parsed JSON: %+v", authResponse)

	log.Info().Msg("Successfully got token")
	log.Debug().Msgf("Extracted Token ID: %s\n", authResponse.Access.Token.ID)
	return authResponse.Access.Token.ID, nil
}

func SetTokenId() error {

	tId, err := GetTokenId()
	if err != nil {
		tokenId = ""
		return err
	}
	tokenId = tId
	log.Info().Msgf("Successfully set token ID")
	log.Debug().Msgf("Token ID: %s", tokenId)
	return nil
}

// GetSecurityGroups function gets a security group.
func GetSecurityGroups(region Region) (string, error) {
	client := resty.New()

	// Set API endpoint
	apiEndpoint := fmt.Sprintf(apiEndpointInfrastructureDocstring, region, Network)
	// Set API URL for security groups
	urlSecurityGroups := fmt.Sprintf("%s/v2.0/security-groups", apiEndpoint)

	// Set Resty
	resp, err := client.R().
		SetHeader("X-Auth-Token", tokenId).
		SetHeader("Content-Type", "application/json").
		Get(urlSecurityGroups)

	if err != nil {
		return "", err
	}
	if err := CheckResponse(resp); err != nil {
		return "", err
	}

	// Print result
	log.Info().Msg("Successfully got security group")
	log.Debug().Msgf("Response Status Code: %d", resp.StatusCode())
	log.Trace().Msgf("Response Body: %s", resp.String())

	return resp.String(), nil
}

// Get a security group
func GetSecurityGroup(region Region, securityGroupId string) (string, error) {
	client := resty.New()

	// Set API endpoint
	apiEndpoint := fmt.Sprintf(apiEndpointInfrastructureDocstring, region, Network)
	// Set API URL for a security group
	urlSecurityGroup := fmt.Sprintf("%s/v2.0/security-groups/%s", apiEndpoint, securityGroupId)

	// Set Resty
	resp, err := client.R().
		SetHeader("X-Auth-Token", tokenId).
		SetHeader("Content-Type", "application/json").
		Get(urlSecurityGroup)

	if err != nil {
		return "", err
	}
	if err := CheckResponse(resp); err != nil {
		return "", err
	}

	// Print result
	log.Info().Msg("Successfully got security group")
	log.Debug().Msgf("Response Status Code: %d", resp.StatusCode())
	log.Debug().Msgf("Response Body: %s", resp.String())

	return resp.String(), nil
}

// Create a security group rule
func CreateSecurityGroupRule(region Region, rule SecurityGroupRule) (string, error) {

	client := resty.New()

	// Set API endpoint
	apiEndpoint := fmt.Sprintf(apiEndpointInfrastructureDocstring, region, Network)
	// Set API URL for a security group
	urlSecurityGroup := fmt.Sprintf("%s/v2.0/security-group-rules", apiEndpoint)

	// Set request body
	reqJsonBytes, err := json.Marshal(rule)
	log.Debug().Msgf("Request Body: %s", reqJsonBytes)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal JSON")
		return "", err
	}

	// Set Resty
	resp, err := client.R().
		SetHeader("X-Auth-Token", tokenId).
		SetHeader("Content-Type", "application/json").
		SetBody(reqJsonBytes).
		Post(urlSecurityGroup)

	if err != nil {
		return "", err
	}
	if err := CheckResponse(resp); err != nil {
		return "", err
	}

	// Print result
	log.Info().Msg("Successfully created security group rule")
	log.Debug().Msgf("Response Status Code: %d", resp.StatusCode())
	log.Trace().Msgf("Response Body: %s", resp.String())

	return resp.String(), nil
}

// Delete a security group rule
func DeleteSecurityGroupRule(region Region, securityGroupRuleId string) error {

	client := resty.New()

	// Set API endpoint
	apiEndpoint := fmt.Sprintf(apiEndpointInfrastructureDocstring, region, Network)
	// Set API URL for a security group
	urlSecurityGroup := fmt.Sprintf("%s/v2.0/security-group-rules/%s", apiEndpoint, securityGroupRuleId)

	// Set Resty
	resp, err := client.R().
		SetHeader("X-Auth-Token", tokenId).
		SetHeader("Content-Type", "application/json").
		Delete(urlSecurityGroup)

	if err != nil {
		return err
	}
	if err := CheckResponse(resp); err != nil {
		return err
	}

	// Print result
	log.Info().Msg("Successfully deleted security group rule")
	log.Debug().Msgf("Response Status Code: %d", resp.StatusCode())
	log.Debug().Msgf("Response Body: %s", resp.String())

	return nil
}

/////////////////////////////////////////////////////////////////////////////////////////

// NOTICE: 2024-01-12, only KR2 region supports Network ACLs

// Model for Network ACLs
type NetworkACLs struct {
	NetworkACL []NetworkACLDetails `json:"acls"`
}

type NetworkACLDetails struct {
	Id             string `json:"id"`
	Name           string `json:"name"`
	Description    string `json:"description"`
	TenantId       string `json:"tenant_id"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
	RevisionNumber int    `json:"revision_number"`
}

// Get Networks ACLs
func GetNetworkACLs(region Region) (string, error) {
	client := resty.New()

	// Set API endpoint
	apiEndpoint := fmt.Sprintf(apiEndpointInfrastructureDocstring, region, Network)
	// Set API URL for security groups
	urlACLs := fmt.Sprintf("%s/v2.0/acls", apiEndpoint)

	// Set Resty
	resp, err := client.R().
		SetHeader("X-Auth-Token", tokenId).
		SetHeader("Content-Type", "application/json").
		Get(urlACLs)

	if err != nil {
		return "", err
	}
	if err := CheckResponse(resp); err != nil {
		return "", err
	}

	// Print result
	log.Info().Msg("Successfully got security group")
	log.Debug().Msgf("Response Status Code: %d", resp.StatusCode())
	log.Trace().Msgf("Response Body: %s", resp.String())

	return resp.String(), nil
}

/////////////////////////////////////////////////////////////////////////////////////////

// Model for load balancer
type LoadBalancers struct {
	LoadBalancers []LoadBalancerDetails `json:"loadbalancers"`
}

type LoadBalancerDetails struct {
	IpaclGroupAction   string         `json:"ipacl_group_action"`
	Description        string         `json:"description"`
	ProvisioningStatus string         `json:"provisioning_status"`
	TenantID           string         `json:"tenant_id"`
	Provider           string         `json:"provider"`
	IpaclGroups        []IPACLGroupId `json:"ipacl_groups"`
	Name               string         `json:"name"`
	LoadBalancerType   string         `json:"loadbalancer_type"`
	Listeners          []Listener     `json:"listeners"`
	VipAddress         string         `json:"vip_address"`
	VipPortID          string         `json:"vip_port_id"`
	WorkflowStatus     string         `json:"workflow_status"`
	VipSubnetID        string         `json:"vip_subnet_id"`
	Id                 string         `json:"id"`
	OperatingStatus    string         `json:"operating_status"`
	AdminStateUp       bool           `json:"admin_state_up"`
}

type IPACLGroupId struct {
	IpaclGroupId string `json:"ipacl_group_id"`
}

type Listener struct {
	Id string `json:"id"`
}

// Models for Binding LoadBalancer and IP ACL groups
type IPACLGroupsBinding struct {
	IpaclGroupsBinding []IPACLGroupId `json:"ipacl_groups_binding"`
}

type BoundPair struct {
	LoadBalancerId string `json:"loadbalancer_id"`
	IpaclGroupId   string `json:"ipacl_group_id"`
}

// Models for IP ACL groups
type IPACLGroups struct {
	IpaclGroups []IPACLGroupDetails `json:"ipacl_groups"`
}

type IPACLGroup struct {
	IpaclGroup IPACLGroupDetails `json:"ipacl_group"`
}

type IPACLGroupDetails struct {
	IpaclTargetCount string           `json:"ipacl_target_count,omitempty"`
	Description      string           `json:"description,omitempty"`
	LoadBalancers    []LoadBalancerId `json:"loadbalancers,omitempty"`
	TenantId         string           `json:"tenant_id,omitempty"`
	Action           string           `json:"action,omitempty"`
	Id               string           `json:"id,omitempty"`
	Name             string           `json:"name,omitempty"`
}

type LoadBalancerId struct {
	LoadBalancerId string `json:"loadbalancer_id"`
}

// Models for IP ACl targets

type IPACLTargets struct {
	IpaclTargets []IPACLTargetDetails `json:"ipacl_targets"`
}

type IPACLTarget struct {
	IpaclTarget IPACLTargetDetails `json:"ipacl_target"`
}

type IPACLTargetDetails struct {
	IpaclGroupId string `json:"ipacl_group_id"`
	TenantId     string `json:"tenant_id,omitempty"`
	CIDRAddress  string `json:"cidr_address"`
	Description  string `json:"description"`
	Id           string `json:"id,omitempty"`
}

// Get load balancers
func GetLoadBalancers(region Region) (string, error) {
	client := resty.New()

	// Set API endpoint
	apiEndpoint := fmt.Sprintf(apiEndpointInfrastructureDocstring, region, Network)
	// Set API URL for security groups
	urlLBs := fmt.Sprintf("%s/v2.0/lbaas/loadbalancers", apiEndpoint)

	// Set Resty
	resp, err := client.R().
		SetHeader("X-Auth-Token", tokenId).
		SetHeader("Content-Type", "application/json").
		Get(urlLBs)

	if err != nil {
		return "", err
	}
	if err := CheckResponse(resp); err != nil {
		return "", err
	}

	// Print result
	log.Info().Msg("Successfully got security group")
	log.Debug().Msgf("Response Status Code: %d", resp.StatusCode())
	log.Trace().Msgf("Response Body: %s", resp.String())

	return resp.String(), nil
}

// Bind IP access control list group (IP ACL group) to load balancer
func BindIpACLGroupToLoadBalancer(region Region, lbId string, bindings IPACLGroupsBinding) (string, error) {
	client := resty.New()

	// Set API endpoint
	apiEndpoint := fmt.Sprintf(apiEndpointInfrastructureDocstring, region, Network)
	// Set API URL for security groups
	urlBinding := fmt.Sprintf("%s/v2.0/lbaas/loadbalancers/%s/bind_ipacl_groups", apiEndpoint, lbId)

	// Set request body
	reqJsonBytes, err := json.Marshal(bindings)
	log.Debug().Msgf("Request Body: %s", reqJsonBytes)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal JSON")
		return "", err
	}

	// Set Resty
	resp, err := client.R().
		SetHeader("X-Auth-Token", tokenId).
		SetHeader("Content-Type", "application/json").
		SetBody(reqJsonBytes).
		Put(urlBinding)

	if err != nil {
		return "", err
	}
	if err := CheckResponse(resp); err != nil {
		return "", err
	}

	// Print result
	log.Info().Msg("Successfully bound IP ACL groups to load balancer")
	log.Debug().Msgf("Response Status Code: %d", resp.StatusCode())
	log.Trace().Msgf("Response Body: %s", resp.String())

	return resp.String(), nil
}

// Get IP access control list groups (IP ACL groups)
func GetIpACLGroups(region Region) (string, error) {
	client := resty.New()

	// Set API endpoint
	apiEndpoint := fmt.Sprintf(apiEndpointInfrastructureDocstring, region, Network)
	// Set API URL
	urlIpACLGroups := fmt.Sprintf("%s/v2.0/lbaas/ipacl-groups", apiEndpoint)

	// Set Resty
	resp, err := client.R().
		SetHeader("X-Auth-Token", tokenId).
		SetHeader("Content-Type", "application/json").
		Get(urlIpACLGroups)

	if err != nil {
		return "", err
	}
	if err := CheckResponse(resp); err != nil {
		return "", err
	}

	// Print result
	log.Info().Msg("Successfully got IP access control list groups (IP ACL groups)")
	log.Debug().Msgf("Response Status Code: %d", resp.StatusCode())
	log.Trace().Msgf("Response Body: %s", resp.String())

	return resp.String(), nil
}

// Create an IP access control list group (IP ACL group)
func CreateIpACLGroup(region Region, group IPACLGroup) (string, error) {

	client := resty.New()

	// Set API endpoint
	apiEndpoint := fmt.Sprintf(apiEndpointInfrastructureDocstring, region, Network)
	// Set API URL
	urlIpACLGroups := fmt.Sprintf("%s/v2.0/lbaas/ipacl-groups", apiEndpoint)

	// Set request body
	reqJsonBytes, err := json.Marshal(group)
	log.Debug().Msgf("Request Body: %s", reqJsonBytes)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal JSON")
		return "", err
	}

	// Set Resty
	resp, err := client.R().
		SetHeader("X-Auth-Token", tokenId).
		SetHeader("Content-Type", "application/json").
		SetBody(reqJsonBytes).
		Post(urlIpACLGroups)

	if err != nil {
		return "", err
	}
	if err := CheckResponse(resp); err != nil {
		return "", err
	}

	// Print result
	log.Info().Msg("Successfully created IP access control list group (IP ACL group)")
	log.Debug().Msgf("Response Status Code: %d", resp.StatusCode())
	log.Trace().Msgf("Response Body: %s", resp.String())

	return resp.String(), nil
}

// Delete IP access control list group (IP ACL group)
func DeleteIpACLGroup(region Region, groupId string) error {

	client := resty.New()

	// Set API endpoint
	apiEndpoint := fmt.Sprintf(apiEndpointInfrastructureDocstring, region, Network)
	// Set API URL
	urlIpACLGroup := fmt.Sprintf("%s/v2.0/lbaas/ipacl-groups/%s", apiEndpoint, groupId)

	// Set Resty
	resp, err := client.R().
		SetHeader("X-Auth-Token", tokenId).
		SetHeader("Content-Type", "application/json").
		Delete(urlIpACLGroup)

	if err != nil {
		return err
	}
	if err := CheckResponse(resp); err != nil {
		return err
	}

	// Print result
	log.Info().Msg("Successfully created IP access control list group (IP ACL group)")
	log.Debug().Msgf("Response Status Code: %d", resp.StatusCode())
	log.Trace().Msgf("Response Body: %s", resp.String())

	return nil
}

// Get IP access control list targets (IP ACL targets)
func GetIpACLTargets(region Region) (string, error) {
	client := resty.New()

	// Set API endpoint
	apiEndpoint := fmt.Sprintf(apiEndpointInfrastructureDocstring, region, Network)
	// Set API URL
	urlIpACLTargets := fmt.Sprintf("%s/v2.0/lbaas/ipacl-targets", apiEndpoint)

	// Set Resty
	resp, err := client.R().
		SetHeader("X-Auth-Token", tokenId).
		SetHeader("Content-Type", "application/json").
		Get(urlIpACLTargets)

	if err != nil {
		return "", err
	}
	if err := CheckResponse(resp); err != nil {
		return "", err
	}

	// Print result
	log.Info().Msg("Successfully got IP access control list targets (IP ACL targets)")
	log.Debug().Msgf("Response Status Code: %d", resp.StatusCode())
	log.Trace().Msgf("Response Body: %s", resp.String())

	return resp.String(), nil
}

// Create IP access control list target (IP ACL target)
func CreateIpACLTarget(region Region, target IPACLTarget) (string, error) {

	client := resty.New()

	// Set API endpoint
	apiEndpoint := fmt.Sprintf(apiEndpointInfrastructureDocstring, region, Network)
	// Set API URL
	urlIpACLTargets := fmt.Sprintf("%s/v2.0/lbaas/ipacl-targets", apiEndpoint)

	// Set request body
	reqJsonBytes, err := json.Marshal(target)
	log.Debug().Msgf("Request Body: %s", reqJsonBytes)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal JSON")
		return "", err
	}

	// Set Resty
	resp, err := client.R().
		SetHeader("X-Auth-Token", tokenId).
		SetHeader("Content-Type", "application/json").
		SetBody(reqJsonBytes).
		Post(urlIpACLTargets)

	if err != nil {
		return "", err
	}
	if err := CheckResponse(resp); err != nil {
		return "", err
	}

	// Print result
	log.Info().Msg("Successfully created IP access control list target (IP ACL target)")
	log.Debug().Msgf("Response Status Code: %d", resp.StatusCode())
	log.Trace().Msgf("Response Body: %s", resp.String())

	return resp.String(), nil

}

// Delete IP access control list target (IP ACL target)
func DeleteIpACLTarget(region Region, targetId string) error {

	client := resty.New()

	// Set API endpoint
	apiEndpoint := fmt.Sprintf(apiEndpointInfrastructureDocstring, region, Network)
	// Set API URL
	urlIpACLTarget := fmt.Sprintf("%s/v2.0/lbaas/ipacl-targets/%s", apiEndpoint, targetId)

	// Set Resty
	resp, err := client.R().
		SetHeader("X-Auth-Token", tokenId).
		SetHeader("Content-Type", "application/json").
		Delete(urlIpACLTarget)

	if err != nil {
		return err
	}
	if err := CheckResponse(resp); err != nil {
		return err
	}

	// Print result
	log.Info().Msg("Successfully created IP access control list target (IP ACL target)")
	log.Debug().Msgf("Response Status Code: %d", resp.StatusCode())
	log.Trace().Msgf("Response Body: %s", resp.String())

	return nil
}
