package config

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

var (
	RuntimeConfig Config
	Knockknock    KnockknockConfig
	Tumblebug     TumblebugConfig
	Keycloak      KeycloakConfig
	JwtAuth       JwtAuthConfig
	Nhncloud      NhncloudConfig
	Slack         SlackConfig
)

type Config struct {
	Knockknock KnockknockConfig `mapstructure:"knockknock"`
	Keycloak   KeycloakConfig   `mapstructure:"keycloak"`
	JwtAuth    JwtAuthConfig    `mapstructure:"jwt"`
	Nhncloud   NhncloudConfig   `mapstructure:"nhncloud"`
	Slack      SlackConfig      `mapstructure:"slack"`
}

// KnockknockConfig - Knock-knock configuration
type KnockknockConfig struct {
	Root string `mapstructure:"root"`

	Self        SelfConfig        `mapstructure:"self"`
	API         ApiConfig         `mapstructure:"api"`
	LogFile     LogfileConfig     `mapstructure:"logfile"`
	LogLevel    string            `mapstructure:"loglevel"`
	LogWriter   string            `mapstructure:"logwriter"`
	Node        NodeConfig        `mapstructure:"node"`
	AutoControl AutoControlConfig `mapstructure:"autocontrol"`
	Tumblebug   TumblebugConfig   `mapstructure:"tumblebug"`
}

type SelfConfig struct {
	Endpoint string `mapstructure:"endpoint"`
}

type ApiConfig struct {
	Allow    AllowConfig `mapstructure:"allow"`
	Auth     AuthConfig  `mapstructure:"auth"`
	Username string      `mapstructure:"username"`
	Password string      `mapstructure:"password"`
}

type AllowConfig struct {
	Origins string `mapstructure:"origins"`
}
type AuthConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

type LkvStoreConfig struct {
	Path string `mapstructure:"path"`
}

type LogfileConfig struct {
	Path       string `mapstructure:"path"`
	MaxSize    int    `mapstructure:"maxsize"`
	MaxBackups int    `mapstructure:"maxbackups"`
	MaxAge     int    `mapstructure:"maxage"`
	Compress   bool   `mapstructure:"compress"`
}

type NodeConfig struct {
	Env string `mapstructure:"env"`
}

type AutoControlConfig struct {
	DurationMilliSec int `mapstructure:"duration_ms"`
}

type TumblebugConfig struct {
	Endpoint string             `mapstructure:"endpoint"`
	RestUrl  string             `mapstructure:"resturl"`
	API      TumblebugApiConfig `mapstructure:"api"`
}

type TumblebugApiConfig struct {
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

// KeycloakConfig - Keycloak configuration
type KeycloakConfig struct {
	Enabled             bool           `mapstructure:"enabled"`
	ServerUrl           string         `mapstructure:"serverUrl"`
	Realm               string         `mapstructure:"realm"`
	AuthUrl             string         `mapstructure:"authUrl"`
	TokenUrl            string         `mapstructure:"tokenUrl"`
	RealmRS256PublicKey string         `mapstructure:"realmRS256PublicKey"`
	ClientId            string         `mapstructure:"clientId"`
	ClientSecret        string         `mapstructure:"clientSecret"`
	RedirectUrl         string         `mapstructure:"redirectUrl"`
	Frontend            FrontendConfig `mapstructure:"frontend"`
	Backend             BackendConfig  `mapstructure:"backend"`
}

type FrontendConfig struct {
	ClientId     string `mapstructure:"clientId"`
	ClientSecret string `mapstructure:"clientSecret"`
	RedirectUrl  string `mapstructure:"redirectUrl"`
}

type BackendConfig struct {
	ClientId     string `mapstructure:"clientId"`
	ClientSecret string `mapstructure:"clientSecret"`
	RedirectUrl  string `mapstructure:"redirectUrl"`
}

// JwtAuthConfig - JWT authentication configuration
type JwtAuthConfig struct {
	Jwt JwtConfig `mapstructure:"jwt"`
}

type JwtConfig struct {
	Signing   SigningConfig `mapstructure:"signing"`
	PublicKey string        `mapstructure:"publickey"`
}

type SigningConfig struct {
	Method string `mapstructure:"method"`
}

// NhncloudConfig - NHN Cloud configuration
type NhncloudConfig struct {
	IdentityEndpoint string `mapstructure:"identityEndpoint"`
	TenantId         string `mapstructure:"tenantId"`
	Username         string `mapstructure:"username"`
	ApiPassword      string `mapstructure:"apiPassword"`
	DomainName       string `mapstructure:"domainName"`
	Url              string `mapstructure:"url"`
	AppKey           string `mapstructure:"appKey"`
}

// SlackConfig - Slack configuration
type SlackConfig struct {
	Token     string `mapstructure:"token"`
	ChannelId string `mapstructure:"channelId"`
}

func Init() {
	viper.AddConfigPath("../../conf/") // config for development
	viper.AddConfigPath(".")           // config for production optionally looking for the configuration in the working directory
	viper.AddConfigPath("./conf/")     // config for production optionally looking for the configuration in the working directory/conf/
	viper.SetConfigType("yaml")

	// Load config
	viper.SetConfigName("config")

	err := viper.ReadInConfig()
	if err != nil {
		log.Printf("no main config file, using default settings: %s", err)
	}

	// Load secrets configuration
	viper.SetConfigName("secrets")
	err = viper.MergeInConfig() // Merge in the secrets config
	if err != nil {
		log.Fatalf("no reading secrets config file: %s", err)
	}

	// Explicitly bind environment variables to configuration keys
	bindEnvironmentVariables()

	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer)
	viper.AutomaticEnv()

	if viper.GetString("knockknock.root") == "" {
		log.Println("Finding project root by using project name")

		projectRoot := findProjectRoot("knock-knock")
		viper.Set("knockknock.root", projectRoot)
	}

	if err := viper.Unmarshal(&RuntimeConfig); err != nil {
		log.Fatalf("Unable to decode into struct: %v", err)
	}
	Knockknock = RuntimeConfig.Knockknock
	Knockknock.Tumblebug.RestUrl = Knockknock.Tumblebug.Endpoint + "/tumblebug"
	Tumblebug = Knockknock.Tumblebug

	Keycloak = RuntimeConfig.Keycloak
	JwtAuth = RuntimeConfig.JwtAuth
	Nhncloud = RuntimeConfig.Nhncloud
	Slack = RuntimeConfig.Slack

	// Print settings if in development mode
	if Knockknock.Node.Env == "development" {
		settings := viper.AllSettings()
		recursivePrintMap(settings, "")
	}

}

func findProjectRoot(projectName string) string {
	execPath, err := os.Executable()
	if err != nil {
		log.Fatalf("Error getting executable path: %v", err)
	}
	execDir := filepath.Dir(execPath)
	projectRoot, err := checkProjectRootInParentDirectory(projectName, execDir)
	if err != nil {
		fmt.Printf("Set current directory as project root directory (%v)\n", err)
		log.Printf("Set current directory as project root directory (%v)", err)
		projectRoot = execDir
	}
	fmt.Printf("Project root directory: %s\n", projectRoot)
	log.Printf("Project root directory: %s\n", projectRoot)
	return projectRoot
}

func checkProjectRootInParentDirectory(projectName string, execDir string) (string, error) {

	// Append a path separator to the project name for accurate matching
	projectNameWithSeparator := projectName + string(filepath.Separator)
	// Find the last index of the project name with the separator
	index := strings.LastIndex(execDir, projectNameWithSeparator)
	if index == -1 {
		return "", errors.New("project name not found in the path")
	}

	// Cut the string up to the index + length of the project name
	result := execDir[:index+len(projectNameWithSeparator)-1]

	return result, nil
}

func recursivePrintMap(m map[string]interface{}, prefix string) {
	for k, v := range m {
		fullKey := prefix + k
		if nestedMap, ok := v.(map[string]interface{}); ok {
			// Recursive call for nested maps
			recursivePrintMap(nestedMap, fullKey+".")
		} else {
			// Print current key-value pair
			log.Printf("Key: %s, Value: %v\n", fullKey, v)
		}
	}
}

func bindEnvironmentVariables() {
	// Explicitly bind environment variables to configuration keys
	viper.BindEnv("knockknock.root", "KNOCKKNOCK_ROOT")
	viper.BindEnv("knockknock.self.endpoint", "KNOCKKNOCK_SELF_ENDPOINT")
	viper.BindEnv("knockknock.api.allow.origins", "KNOCKKNOCK_API_ALLOW_ORIGINS")
	viper.BindEnv("knockknock.api.auth.enabled", "KNOCKKNOCK_API_AUTH_ENABLED")
	viper.BindEnv("knockknock.api.username", "KNOCKKNOCK_API_USERNAME")
	viper.BindEnv("knockknock.api.password", "KNOCKKNOCK_API_PASSWORD")
	viper.BindEnv("knockknock.logfile.path", "KNOCKKNOCK_LOGFILE_PATH")
	viper.BindEnv("knockknock.logfile.maxsize", "KNOCKKNOCK_LOGFILE_MAXSIZE")
	viper.BindEnv("knockknock.logfile.maxbackups", "KNOCKKNOCK_LOGFILE_MAXBACKUPS")
	viper.BindEnv("knockknock.logfile.maxage", "KNOCKKNOCK_LOGFILE_MAXAGE")
	viper.BindEnv("knockknock.logfile.compress", "KNOCKKNOCK_LOGFILE_COMPRESS")
	viper.BindEnv("knockknock.loglevel", "KNOCKKNOCK_LOGLEVEL")
	viper.BindEnv("knockknock.logwriter", "KNOCKKNOCK_LOGWRITER")
	viper.BindEnv("knockknock.node.env", "KNOCKKNOCK_NODE_ENV")
	viper.BindEnv("knockknock.autocontrol.duration_ms", "KNOCKKNOCK_AUTOCONTROL_DURATION_MS")
	viper.BindEnv("knockknock.tumblebug.endpoint", "KNOCKKNOCK_TUMBLEBUG_ENDPOINT")
	viper.BindEnv("knockknock.tumblebug.api.username", "KNOCKKNOCK_TUMBLEBUG_API_USERNAME")
	viper.BindEnv("knockknock.tumblebug.api.password", "KNOCKKNOCK_TUMBLEBUG_API_PASSWORD")
}
