package nhnutil

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"

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
	SecurityGroups []SecurityGroup `json:"security_groups"`
}

type SecurityGroup struct {
	TenantId           string              `json:"tenant_id"`
	Description        string              `json:"description"`
	Id                 string              `json:"id"`
	SecurityGroupRules []SecurityGroupRule `json:"security_group_rules"`
	Name               string              `json:"name"`
}
type SecurityGroupRule struct {
	Direction       string `json:"direction"`
	Protocol        string `json:"protocol"`
	Description     string `json:"description"`
	PortRangeMax    int    `json:"port_range_max"`
	Id              string `json:"id"`
	RemoteGroupId   string `json:"remote_group_id"`
	RemoteIpPrefix  string `json:"remote_ip_prefix"`
	SecurityGroupId string `json:"security_group_id"`
	TenantId        string `json:"tenant_id"`
	PortRangeMin    int    `json:"port_range_min"`
	Ethertype       string `json:"ethertype"`
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
		log.Error().Err(err).Msg("Failed to get token")
		return "", err
	}

	log.Info().Msg("Successfully got token")
	log.Debug().Msgf("Response Status Code: %d", resp.StatusCode())
	log.Debug().Msgf("Response Body: %s", resp.String())

	if resp.StatusCode() < http.StatusOK || resp.StatusCode() >= http.StatusMultipleChoices {
		// 2xx status codes indicate success, no error
		log.Error().Err(errors.New(resp.String())).Msg("Failed to get token")
		return "", errors.New(resp.String())
	}

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
		log.Error().Err(err).Msg("Failed to get security group")
		return "", err
	}

	// Print result
	log.Info().Msg("Successfully got security group")
	log.Debug().Msgf("Response Status Code: %d", resp.StatusCode())
	log.Debug().Msgf("Response Body: %s", resp.String())

	if resp.StatusCode() < http.StatusOK || resp.StatusCode() >= http.StatusMultipleChoices {
		// 2xx status codes indicate success, no error
		log.Error().Err(errors.New(resp.String())).Msg("Failed to get security group")

		return "", errors.New(resp.String())
	}

	return resp.String(), nil
}

// GetSecurityGroup function gets a security group.
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
		log.Error().Err(err).Msg("Failed to get security group")
		return "", err
	}

	// Print result
	log.Info().Msg("Successfully got security group")
	log.Debug().Msgf("Response Status Code: %d", resp.StatusCode())
	log.Debug().Msgf("Response Body: %s", resp.String())

	if resp.StatusCode() < http.StatusOK || resp.StatusCode() >= http.StatusMultipleChoices {
		// 2xx status codes indicate success, no error
		log.Error().Err(errors.New(resp.String())).Msg("Failed to get security group")
		return "", errors.New(resp.String())
	}

	return resp.String(), nil
}

// GenSecurityGroup function creates an NHN Cloud security group.
func GenSecurityGroup(securityGroupName string) {
	tfConfig := fmt.Sprintf(`
resource "nhncloud_security_group" "%s" {
	name        = "%s"
	description = "Security group for %s"
	// Add necessary security rules here.
}
`, securityGroupName, securityGroupName, securityGroupName)

	createTerraformFile(filenameSecurityGroup, tfConfig)
}

// UpdateSecurityGroup 함수는 securityGroup 파일을 업데이트합니다.
func UpdateSecurityGroup(securityGroupName, newRule string) error {
	filePath := filenameSecurityGroup
	updatedContent, err := addNewRuleToSecurityGroup(filePath, securityGroupName, newRule)
	if err != nil {
		return err
	}

	return overwriteFile(filePath, updatedContent)
}

// addNewRuleToSecurityGroup 함수는 보안 그룹에 새로운 규칙을 추가합니다.
func addNewRuleToSecurityGroup(filePath, securityGroupName, newRule string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var updatedLines []string
	scanner := bufio.NewScanner(file)
	insideBlock := false

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, fmt.Sprintf(`resource "nhncloud_security_group" "%s" {`, securityGroupName)) {
			insideBlock = true
		}

		if insideBlock && strings.Contains(line, "}") {
			updatedLines = append(updatedLines, newRule) // 새로운 규칙 추가
			insideBlock = false
		}

		updatedLines = append(updatedLines, line)
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return strings.Join(updatedLines, "\n"), nil
}

// overwriteFile 함수는 파일의 내용을 덮어씁니다.
func overwriteFile(filePath, content string) error {
	return os.WriteFile(filePath, []byte(content), 0644)
}

// AttachSecurityGroup function attaches a security group to a specific resource.
func AttachSecurityGroup(resourceType, resourceName, securityGroupName string) {
	tfConfig := fmt.Sprintf(`
resource "%s" "%s" {
	// Add resource details here.

	security_group = nhncloud_security_group.%s.id
}
`, resourceType, resourceName, securityGroupName)

	createTerraformFile(filenameAttachSecurityGroup, tfConfig)
}

// createTerraformFile function creates a Terraform file with the given content.
func createTerraformFile(fileName, content string) {
	file, err := os.Create(fileName)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	_, err = file.WriteString(content)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Terraform configuration file '%s' created.\n", fileName)
}

// TerraformApply function applies the Terraform configuration.
func TerraformApply() {
	cmd := exec.Command("terraform", "apply", "-auto-approve")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		panic(err)
	}
}
