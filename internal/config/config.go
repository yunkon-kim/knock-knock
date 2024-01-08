package config

import (
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

func init() {
	Init()
}

func Init() {
	viper.AddConfigPath("../../conf/") // config for development
	viper.AddConfigPath(".")           // config for production optionally looking for the configuration in the working directory
	viper.AddConfigPath("./conf/")     // config for production optionally looking for the configuration in the working directory/conf/
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")

	// Map environment variable names to config file key names
	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer)

	// Automatically recognize environment variables
	viper.AutomaticEnv()

	// Try to read the config file in development environment
	if viper.GetString("node.env") != "production" {
		if err := viper.ReadInConfig(); err != nil {
			log.Printf("Error reading config file, using default settings: %s", err)
		}
	}

	// Values set in runtime
	if viper.GetString("knockknock.root") == "" {
		log.Println("find project root by using project name")

		projectName := "knock-knock"
		// Get the executable path
		execPath, err := os.Executable()
		if err != nil {
			log.Fatalf("Error getting executable path: %v", err)
		}
		execDir := filepath.Dir(execPath)
		projectRoot, err := checkProjectRootInParentDirectory(projectName, execDir)
		if err != nil {
			log.Printf("set current directory as project root directory (%v)", err)
			projectRoot = execDir
		}
		log.Printf("project root directory: %s\n", projectRoot)
		// Set the binary path
		viper.Set("knockknock.root", projectRoot)
		viper.Set("apidoc.path", projectRoot+"/pkg/api/rest/docs/swagger.json")
	}

	// Recursively print all keys and values in Viper
	settings := viper.AllSettings()
	recursivePrintMap(settings, "")
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
