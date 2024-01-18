// Package main is the starting point of knock-knock
package main

import (
	"flag"
	"os"
	"strconv"
	"sync"

	// Black import (_) is for running a package's init() function without using its other contents.
	"github.com/rs/zerolog/log"
	_ "github.com/yunkon-kim/knock-knock/internal/config"
	_ "github.com/yunkon-kim/knock-knock/internal/logger"

	//_ "github.com/go-sql-driver/mysql"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"

	restServer "github.com/yunkon-kim/knock-knock/pkg/api/rest/server"
	frontendServer "github.com/yunkon-kim/knock-knock/web/server"
)

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

	//Setup database (meta_db/dat/knockknock.s3db)
	log.Info().Msg("setting SQL Database")
	err := os.MkdirAll("./meta_db/dat/", os.ModePerm)
	if err != nil {
		log.Error().Err(err).Msg("error creating directory")
	}
	log.Debug().Msgf("database file path: %s", "./meta_db/dat/knockknock.s3db")

	// Watch config file changes
	go func() {
		viper.WatchConfig()
		viper.OnConfigChange(func(e fsnotify.Event) {
			log.Debug().Str("file", e.Name).Msg("config file changed")
			err := viper.ReadInConfig()
			if err != nil { // Handle errors reading the config file
				log.Fatal().Err(err).Msg("fatal error in config file")
			}
			// err = viper.Unmarshal(&common.RuntimeConf)
			if err != nil {
				log.Panic().Err(err).Msg("error unmarshaling runtime configuration")
			}
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

	wg.Wait()
}
