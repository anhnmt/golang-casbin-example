package config

import (
	"github.com/spf13/viper"
)

// defaultConfig is the default configuration for the application.
func defaultConfig() {
	// APP
	viper.SetDefault("APP_PORT", 8000)
	// DATABASE
	viper.SetDefault("DB_URL", "mongodb://localhost:27017")
	viper.SetDefault("DB_NAME", "casbin")

	viper.SetDefault("MODEL_PATH", "config/model_policy.conf")
}
