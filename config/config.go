package config

import (
	"runtime"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

// NewConfig initializes the config
func NewConfig() {
	viper.AutomaticEnv()

	// Replace env key, exp: database.url -> database_url
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))

	viper.AddConfigPath(".")
	viper.SetConfigFile(".env")
	viper.SetConfigType("env")

	if err := viper.ReadInConfig(); err != nil {
		log.Fatal().Err(err).Msg("Error reading config file")
	}

	// set default config
	defaultConfig()

	log.Info().
		Str("goarch", runtime.GOARCH).
		Str("goos", runtime.GOOS).
		Str("version", runtime.Version()).
		Msg("Runtime information")
}
