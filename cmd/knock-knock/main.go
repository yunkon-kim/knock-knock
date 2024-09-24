// Package main is the starting point of knock-knock
package main

import (
	"flag"
	"strconv"
	"sync"
	"time"

	// Black import (_) is for running a package's init() function without using its other contents.
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
	"github.com/yunkon-kim/knock-knock/internal/config"
	"github.com/yunkon-kim/knock-knock/internal/logger"
	"github.com/yunkon-kim/knock-knock/internal/slack"

	//_ "github.com/go-sql-driver/mysql"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"

	restServer "github.com/yunkon-kim/knock-knock/pkg/api/rest/server"
	"github.com/yunkon-kim/knock-knock/pkg/nhnutil"
	frontendServer "github.com/yunkon-kim/knock-knock/web/server"
)

// NoOpLogger is an implementation of resty.Logger that discards all logs.
type NoOpLogger struct{}

func (n *NoOpLogger) Errorf(format string, v ...interface{}) {}
func (n *NoOpLogger) Warnf(format string, v ...interface{})  {}
func (n *NoOpLogger) Debugf(format string, v ...interface{}) {}

func init() {
	config.Init()
	// Initialize the logger
	logger := logger.NewLogger(logger.Config{
		LogLevel:    config.Knockknock.LogLevel,
		LogWriter:   config.Knockknock.LogWriter,
		LogFilePath: config.Knockknock.LogFile.Path,
		MaxSize:     config.Knockknock.LogFile.MaxSize,
		MaxBackups:  config.Knockknock.LogFile.MaxBackups,
		MaxAge:      config.Knockknock.LogFile.MaxAge,
		Compress:    config.Knockknock.LogFile.Compress,
	})

	// Set the global logger
	log.Logger = *logger

	// Initialize Slack
	slack.Init(slack.Config{
		Token:     config.Slack.Token,
		ChannelId: config.Slack.ChannelId,
	})

	// Initialize NHN cloud
	nhnutil.Init(nhnutil.Config{
		TenantId:    config.Nhncloud.TenantId,
		Username:    config.Nhncloud.Username,
		ApiPassword: config.Nhncloud.ApiPassword,
	})

	// Check Tumblebug readiness
	apiUrl := config.Tumblebug.RestUrl + "/readyz"
	isReady, err := checkReadiness(apiUrl)

	if err != nil || !isReady {
		log.Fatal().Err(err).Msg("Tumblebug is not ready. Exiting...")
	}

	log.Info().Msg("Tumblebug is ready. Initializing Beetle...")
}

func checkReadiness(url string) (bool, error) {
	// Create a new resty client
	client := resty.New()

	// Disable Resty default logging by setting a no-op logger
	client.SetLogger(&NoOpLogger{})

	// Set for retries
	retryMaxAttempts := 20
	retryWaitTime := 3 * time.Second
	retryMaxWaitTime := 80 * time.Second
	// Configure retries
	client.
		// Set retry count to non zero to enable retries
		SetRetryCount(retryMaxAttempts).
		// You can override initial retry wait time.
		// Default is 100 milliseconds.
		SetRetryWaitTime(retryWaitTime).
		// MaxWaitTime can be overridden as well.
		// Default is 2 seconds.
		SetRetryMaxWaitTime(retryMaxWaitTime).
		// SetRetryAfter sets callback to calculate wait time between retries.
		// Default (nil) implies exponential backoff with jitter
		SetRetryAfter(func(client *resty.Client, resp *resty.Response) (time.Duration, error) {
			attempt := resp.Request.Attempt // Current attempt number
			maxAttempts := retryMaxAttempts // Maximum attempt number

			log.Info().Msgf("check readiness by %s. Attempt %d/%d.",
				resp.Request.URL, attempt, maxAttempts)

			// Always retry after the calculated wait time
			return retryWaitTime, nil
		})

	resp, err := client.R().Get(url)

	if err != nil || resp.IsError() {
		log.Error().Err(err).Msgf("failed to check readiness by %s", url)
		return false, err
	}

	return true, nil
}

func main() {

	log.Info().Msg("starting knock-knock server")

	// Set the default backendPort number "8056" for the REST API server to listen on
	backendPort := flag.String("backendPort", "8056", "port number for the restapiserver to listen to")
	flag.Parse()

	// Validate port
	if portInt, err := strconv.Atoi(*backendPort); err != nil || portInt < 1 || portInt > 65535 {
		log.Fatal().Msgf("%s is not a valid port number. Please retry with a valid port number (ex: -port=[1-65535]).", *backendPort)
	}
	log.Debug().Msgf("backend port number: %s", *backendPort)

	// Set the default frontendPort number "8888" for the REST API server to listen on
	frontendPort := flag.String("frontendPort", "8888", "port number for the frontendServer to listen to")
	flag.Parse()

	// Validate port
	if portInt, err := strconv.Atoi(*frontendPort); err != nil || portInt < 1 || portInt > 65535 {
		log.Fatal().Msgf("%s is not a valid port number. Please retry with a valid port number (ex: -port=[1-65535]).", *backendPort)
	}
	log.Debug().Msgf("frontend port number: %s", *frontendPort)

	// Watch config file changes
	go func() {
		viper.WatchConfig()
		viper.OnConfigChange(func(e fsnotify.Event) {
			log.Debug().Str("file", e.Name).Msg("config file changed")
			err := viper.ReadInConfig()
			if err != nil { // Handle errors reading the config file
				log.Fatal().Err(err).Msg("fatal error in config file")
			}
			err = viper.Unmarshal(&config.RuntimeConfig)
			if err != nil {
				log.Panic().Err(err).Msg("error unmarshaling runtime configuration")
			}
			config.Knockknock = config.RuntimeConfig.Knockknock
			config.Knockknock.Tumblebug.RestUrl = config.Knockknock.Tumblebug.Endpoint + "/tumblebug"
			config.Tumblebug = config.Knockknock.Tumblebug

			config.Keycloak = config.RuntimeConfig.Keycloak
			config.JwtAuth = config.RuntimeConfig.JwtAuth
			config.Nhncloud = config.RuntimeConfig.Nhncloud
			config.Slack = config.RuntimeConfig.Slack
		})
	}()

	// Launch API servers (REST)
	wg := new(sync.WaitGroup)

	wg.Add(1)
	// Start REST Server
	go func() {
		restServer.RunServer(*backendPort)
		wg.Done()
	}()

	wg.Add(1)
	// Start Frontend Server
	go func() {
		frontendServer.RunFrontendServer(*frontendPort)
		wg.Done()
	}()

	time.Sleep(1 * time.Second)
	restServer.DisplayEndpoints()
	frontendServer.DisplayEndpoints()

	wg.Wait()
}
